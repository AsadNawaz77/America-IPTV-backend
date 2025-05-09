const jwt = require("jsonwebtoken");
const express = require("express");
const nodemailer = require("nodemailer");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const cors = require("cors");
const dotenv = require("dotenv");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const xss = require("xss-clean");
const bcrypt = require("bcryptjs");
const { body, validationResult } = require("express-validator");
const cron = require("node-cron");
const moment = require("moment");
const axios = require("axios");

dotenv.config();
const app = express();
const port = process.env.PORT || 5000;

// Connect to MySQL
const connection = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// connection.connect((err) => {
//   if (err) {
//     console.error("DB connection failed:", err);
//     process.exit(1);
//   }
//   console.log("Connected to MySQL");
// });

// === MIDDLEWARE ===

app.use(cors());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(helmet()); // Secure HTTP headers
app.use(xss()); // Prevent XSS attacks

// Rate limit: max 5 requests per minute per IP (adjust if needed)
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW || "1") * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX || "5"),
  message: "Too many requests, try again later.",
});
app.use(limiter);

// Middleware for verifying JWT token
const verifyToken = (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ error: "Access denied, token required" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Attach decoded user info to request
    next();
  } catch (err) {
    return res.status(400).json({ error: "Invalid token" });
  }
};

// === ROUTES ===
// For Location
app.get("/get-location", async (req, res) => {
  try {
    // 1. Get the user's IP addre
    // ss (from the request header)
    const clientIp = req.headers["x-forwarded-for"]
      ? req.headers["x-forwarded-for"].split(",")[0]
      : req.socket.remoteAddress;
    // 2. Use the real IP to fetch the location
    const locRes = await axios.get(
      `https://ipinfo.io/${clientIp}/json?token=${process.env.TOKEN}`
    );
    console.log(locRes.data);

    // 3. Send country data
    res.json({
      country: locRes.data.country, // Send country code in response
    });
  } catch (err) {
    console.error("Location fetch error:", err.message);
    res.status(500).json({ error: "Failed to fetch location" });
  }
});

// 1. User Submission
app.post(
  "/submit-user",
  [
    body("email").isEmail(),
    body("phone").isLength({ min: 5 }),
    body("name").notEmpty(),
    body("plan").notEmpty(),
    body("Price")
      .trim()
      .matches(/^[\$\€\¥\£]?\d+(\.\d{1,2})?$/)
      .withMessage("Invalid price format"),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res
        .status(400)
        .json({ message: "Invalid data", errors: errors.array() });
    }

    const { Price, email, name, phone, plan } = req.body;
    console.log({ Price, email, name, phone, plan });
    const checkEmailPhoneQuery =
      "SELECT email, phone FROM users WHERE email = ? OR phone = ?";
    connection.query(checkEmailPhoneQuery, [email, phone], (err, results) => {
      if (err) return res.status(500).json({ message: "Database error" });

      if (results.length > 0) {
        const existing = results[0];
        if (existing.email === email && existing.phone === phone) {
          return res.status(400).json({
            field: "both",
            message: "Email and phone are already registered",
          });
        } else if (existing.email === email) {
          return res
            .status(400)
            .json({ field: "email", message: "Email already registered" });
        } else if (existing.phone === phone) {
          return res.status(400).json({
            field: "phone",
            message: "Phone number already registered",
          });
        }
      }

      const timestamp = Date.now();
      const randomDigits = Math.floor(1000 + Math.random() * 9000);
      const invoiceNumber = `INV-${timestamp}-${randomDigits}`;

      // Set invoice status based on plan
      const invoiceStatus = plan === "Free Trial" ? "Free" : "pending";

      const insertQuery = `
        INSERT INTO users (name, email, phone, plan, Price, invoice, invoice_status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `;

      connection.query(
        insertQuery,
        [name, email, phone, plan, Price, invoiceNumber, invoiceStatus],
        async (err, results) => {
          console.error("Insert Error:", err);
          if (err) return res.status(500).json({ message: "Insert failed" });

          // Send email
          const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
              user: process.env.EMAIL_USER,
              pass: process.env.EMAIL_PASS,
            },
          });

          const mailOptions = {
            from: `"America IPTV" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: "Thank you for your purchase!",
            html: `
              <h3>Hi ${name},</h3>
              <p>Thank you for choosing our service!</p>
              <p><strong>Invoice Number:</strong> ${invoiceNumber}</p>
              <p>Plan: ${plan}</p>
              <p>Price: ${Price}</p>
              <br />
              <p>Next step: Click the link below to send your invoice via WhatsApp:</p>
              <a href="https://wa.me/447466036656?text=Hi,%20my%20invoice%20number%20is%20${invoiceNumber}" target="_blank">
                Send Invoice on WhatsApp
              </a>
              <br/><br/>
              <p>Regards,<br/>Team</p>
            `,
          };

          try {
            const info = await transporter.sendMail(mailOptions);
            console.log("Email sent:", info.response);
          } catch (emailErr) {
            console.error("Email sending error:", emailErr);
          }

          res.status(200).json({
            invoice: invoiceNumber,
            message: "Invoice generated and email sent",
          });
        }
      );
    });
  }
);

// 2. Admin Login (JWT Token Returned)
app.post(
  "/admin-login",
  [body("email").isEmail(), body("password").notEmpty()],
  (req, res) => {
    const { email, password } = req.body;

    connection.query(
      "SELECT * FROM admin WHERE email = ?",
      [email],
      async (err, results) => {
        console.log(err);
        if (err) return res.status(500).json({ error: "DB error" });

        if (results.length === 0) {
          return res.status(401).json({ error: "Invalid credentials" });
        }

        const admin = results[0];
        const isMatch = await bcrypt.compare(password, admin.password);

        if (!isMatch) {
          return res.status(401).json({ error: "Invalid credentials" });
        }

        // JWT generation
        const token = jwt.sign(
          { id: admin.id, email: admin.email },
          process.env.JWT_SECRET,
          { expiresIn: "1h" }
        );

        res.status(200).json({
          message: "Login successful",
          token, // Send token to the client
        });
      }
    );
  }
);

// 3. Get Users (Protected route)

app.get("/get-users", verifyToken, (req, res) => {
  const query =
    "SELECT id, name, plan, invoice_status, phone, updated_at FROM users";

  connection.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: "Query error" });

    const updates = [];
    const currentDate = moment().startOf("day");

    results.forEach((user) => {
      const updatedAt = moment(user.updated_at).startOf("day");
      let dueDate;

      if (user.invoice_status === "paid") {
        if (user.plan.includes("Monthly")) {
          dueDate = updatedAt.clone().add(1, "month");
        } else if (user.plan.includes("6-Month")) {
          dueDate = updatedAt.clone().add(6, "months");
        } else if (user.plan.includes("Yearly")) {
          dueDate = updatedAt.clone().add(1, "year");
        }
      }

      // 👉 Handle Free Trial expiry: 7-day period
      if (user.invoice_status === "Free" && user.plan === "Free Trial") {
        dueDate = updatedAt.clone().add(7, "days");
      }

      // Common condition: if dueDate is past
      if (dueDate && dueDate.isBefore(currentDate)) {
        updates.push(user.id);
      }
    });

    if (updates.length > 0) {
      const updateQuery = `UPDATE users SET invoice_status = 'pending' WHERE id IN (?)`;
      connection.query(updateQuery, [updates], (updateErr) => {
        if (updateErr) return res.status(500).json({ error: "Update error" });

        // Re-fetch updated user data
        connection.query(query, (reQueryErr, updatedResults) => {
          if (reQueryErr)
            return res.status(500).json({ error: "Final query error" });

          res.status(200).json({ users: updatedResults });
        });
      });
    } else {
      res.status(200).json({ users: results });
    }
  });
});

// 4. Update Status (Protected route)
app.put("/update-status/:id", verifyToken, (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!status) {
    return res.status(400).json({ error: "Invoice status required" });
  }

  // Step 1: Get user details from the database
  const getUserQuery = "SELECT name, plan, email FROM users WHERE id = ?";
  connection.query(getUserQuery, [id], async (err, results) => {
    if (err) {
      return res.status(500).json({ error: "Database error" });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = results[0]; // user details: name, plan, email

    // Step 2: Update the invoice status in the database
    const updateStatusQuery =
      "UPDATE users SET invoice_status = ? WHERE id = ?";
    connection.query(
      updateStatusQuery,
      [status, id],
      async (err2, updateResults) => {
        if (err2) {
          return res.status(500).json({ error: "Update failed" });
        }

        if (updateResults.affectedRows === 0) {
          return res.status(404).json({ error: "User not found" });
        }

        // Step 3: Calculate the start and end date if the plan is paid
        let startDate = new Date();
        let endDate = new Date();

        const getPlanDuration = (plan) => {
          if (plan.includes("Monthly")) return { months: 1 };
          if (plan.includes("6-Month")) return { months: 6 };
          if (plan.includes("Yearly")) return { years: 1 };
          return null; // Unknown plan
        };
        if (status === "paid") {
          const duration = getPlanDuration(user.plan);
          if (duration) {
            if (duration.months)
              endDate.setMonth(endDate.getMonth() + duration.months);
            if (duration.years)
              endDate.setFullYear(endDate.getFullYear() + duration.years);
          }
        }

        // Step 4: Send appropriate email based on status (only for 'paid')
        const transporter = nodemailer.createTransport({
          service: "gmail",
          auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
          },
        });

        let subject, html;
        if (status === "paid") {
          subject = "Your Payment is Confirmed!";
          html = `
            <h3>Hi ${user.name},</h3>
            <p>Thank you for your payment!</p>
            <p>Your subscription is now active and valid from <strong>${startDate.toDateString()}</strong> to <strong>${endDate.toDateString()}</strong>.</p>
            <p>Enjoy our service!</p>
          `;
        }

        try {
          const info = await transporter.sendMail({
            from: `"America IPTV" <${process.env.EMAIL_USER}>`,
            to: user.email,
            subject,
            html,
          });
          console.log("Email sent:", info.response);
        } catch (emailErr) {
          console.error("Email sending error:", emailErr);
        }

        res.status(200).json({ message: "Status updated and email sent" });
      }
    );
  });
});

// 5. Delete User Route (This handles cancellation logic and sends the cancellation email)
app.delete("/delete-user/:id", verifyToken, (req, res) => {
  const userId = req.params.id;

  // Step 1: Get user details before deletion to send the cancellation email
  const getUserQuery = "SELECT name, plan, email FROM users WHERE id = ?";
  connection.query(getUserQuery, [userId], async (err, results) => {
    if (err) {
      return res.status(500).json({ error: "Database error" });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = results[0]; // user details: name, plan, email

    // Step 2: Delete the user from the database
    connection.query(
      "DELETE FROM users WHERE id = ?",
      [userId],
      async (err2, deleteResults) => {
        if (err2) {
          return res.status(500).json({ message: "Delete failed" });
        }

        if (deleteResults.affectedRows === 0) {
          return res.status(404).json({ message: "User not found" });
        }

        // Step 3: Send cancellation email
        const transporter = nodemailer.createTransport({
          service: "gmail",
          auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
          },
        });

        let subject = "Your Subscription is Cancelled";
        let html = `
          <h3>Hi ${user.name},</h3>
          <p>We're sorry to inform you that your subscription has been cancelled.</p>
          <p>If you wish to re-subscribe in the future, please feel free to reach out to us!</p>
        `;

        try {
          const info = await transporter.sendMail({
            from: `"America IPTV" <${process.env.EMAIL_USER}>`,
            to: user.email,
            subject,
            html,
          });
          console.log("Cancellation email sent:", info.response);
        } catch (emailErr) {
          console.error("Email sending error:", emailErr);
        }

        res
          .status(200)
          .json({ message: "User deleted and cancellation email sent" });
      }
    );
  });
});
// 6. Get latest 3 blogs
app.get("/get-blogs", (req, res) => {
  console.log("HELLOP");
  const query = `
  SELECT id, title, image_url, intro
  FROM blogs
  ORDER BY id DESC
  LIMIT 3
`;

  connection.query(query, (err, results) => {
    if (err) {
      console.error("Blog fetch error:", err);
      return res.status(500).json({ error: "Failed to fetch blogs" });
    }

    res.status(200).json({ blogs: results });
  });
});
// Get all blogs
app.get("/blogs", (req, res) => {
  console.log("HELLOP");
  const query = `
  SELECT *
  FROM blogs
  
`;

  connection.query(query, (err, results) => {
    if (err) {
      console.error("Blog fetch error:", err);
      return res.status(500).json({ error: "Failed to fetch blogs" });
    }

    res.status(200).json({ blogs: results });
  });
});

// Get Spcific Blog
app.get("/blogs/:id", (req, res) => {
  const blogId = req.params.id;

  const query = `
    SELECT 
      b.id AS blogId, b.title, b.image_url, b.intro,
      s.id AS sectionId, s.heading, s.content
    FROM blogs b
    LEFT JOIN blog_sections s ON b.id = s.blog_id
    WHERE b.id = ?
  `;

  connection.query(query, [blogId], (err, results) => {
    if (err) {
      return res
        .status(500)
        .json({ error: "Database query failed", details: err });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "Blog not found" });
    }

    const blog = {
      id: results[0].blogId,
      title: results[0].title,
      image: results[0].image_url, // Use image_url here
      intro: results[0].intro,
      sections: results
        .filter((row) => row.sectionId !== null)
        .map((row) => ({
          id: row.sectionId,
          heading: row.heading,
          content: row.content,
        })),
    };

    res.status(200).json({ blog: blog }); // response key should match frontend
  });
});

// Delete blog
app.delete("/delete-blog/:id", verifyToken, (req, res) => {
  const blogId = req.params.id;

  // Delete related sections first
  const deleteSectionsQuery = "DELETE FROM blog_sections WHERE blog_id = ?";
  connection.query(deleteSectionsQuery, [blogId], (err, result) => {
    if (err) {
      return res
        .status(500)
        .json({ error: "Failed to delete blog sections", details: err });
    }

    // Now delete the blog itself
    const deleteBlogQuery = "DELETE FROM blogs WHERE id = ?";
    connection.query(deleteBlogQuery, [blogId], (err, result) => {
      if (err) {
        return res
          .status(500)
          .json({ error: "Failed to delete blog", details: err });
      }

      res.status(200).json({
        message: "Blog and related sections deleted successfully",
      });
    });
  });
});

// Update blog

app.put("/update-blog/:id", verifyToken, (req, res) => {
  const blogId = req.params.id;
  const { title, image, intro, sections } = req.body;

  // Step 1: Update blog info
  connection.query(
    "UPDATE blogs SET title = ?, image_url = ?, intro = ? WHERE id = ?",
    [title, image, intro, blogId],
    (err) => {
      if (err) {
        return res.status(500).json({ error: "Failed to update blog" });
      }

      // Step 2: Delete removed sections
      const sectionIds = sections.filter((s) => s.id).map((s) => s.id);
      const deleteQuery = sectionIds.length
        ? "DELETE FROM blog_sections WHERE blog_id = ? AND id NOT IN (?)"
        : "DELETE FROM blog_sections WHERE blog_id = ?";

      connection.query(
        deleteQuery,
        sectionIds.length ? [blogId, sectionIds] : [blogId],
        (err) => {
          if (err) {
            return res
              .status(500)
              .json({ error: "Failed to delete old sections" });
          }

          // Step 3: Split into new vs existing sections
          const newSections = sections.filter((s) => !s.id);
          const existingSections = sections.filter((s) => s.id);

          // Step 4: Insert new sections
          const insertNew = (cb) => {
            if (newSections.length === 0) return cb();

            const newValues = newSections.map((s) => [
              blogId,
              s.heading,
              s.content,
            ]);
            connection.query(
              "INSERT INTO blog_sections (blog_id, heading, content) VALUES ?",
              [newValues],
              cb
            );
          };

          // Step 5: Upsert existing sections
          const upsertExisting = (cb) => {
            if (existingSections.length === 0) return cb();

            const existingValues = existingSections.map((s) => [
              blogId,
              s.heading,
              s.content,
              s.id,
            ]);
            connection.query(
              `INSERT INTO blog_sections (blog_id, heading, content, id)
             VALUES ?
             ON DUPLICATE KEY UPDATE heading = VALUES(heading), content = VALUES(content)`,
              [existingValues],
              cb
            );
          };

          // Step 6: Run both
          insertNew((err) => {
            if (err) {
              console.error(err);
              return res
                .status(500)
                .json({ error: "Failed to insert new sections" });
            }
            upsertExisting((err) => {
              if (err) {
                console.error(err);
                return res
                  .status(500)
                  .json({ error: "Failed to update existing sections" });
              }
              res
                .status(200)
                .json({ message: "Blog and sections updated successfully" });
            });
          });
        }
      );
    }
  );
});

// Add new blog
app.post("/add-blog", verifyToken, (req, res) => {
  const { title, image, intro, sections } = req.body;

  if (!title || !sections || !Array.isArray(sections)) {
    return res.status(400).json({ error: "Title and sections are required" });
  }

  if (sections.length === 0) {
    return res.status(400).json({ error: "At least one section is required" });
  }

  // Step 1: Check if blog with same title exists
  connection.query(
    "SELECT id FROM blogs WHERE title = ?",
    [title],
    (err, results) => {
      if (err) {
        console.error(err);
        return res
          .status(500)
          .json({ error: "Database error while checking blog" });
      }

      if (results.length > 0) {
        return res
          .status(409)
          .json({ error: "Blog with this title already exists" });
      }

      // Step 2: Insert the blog
      connection.query(
        "INSERT INTO blogs (title, image_url, intro) VALUES (?, ?, ?)",
        [title, image, intro],
        (err, result) => {
          if (err) {
            console.error(err);
            return res.status(500).json({ error: "Failed to insert blog" });
          }

          const blogId = result.insertId;

          // Step 3: Insert blog sections
          const sectionValues = sections.map((section) => [
            blogId,
            section.heading,
            section.content,
          ]);

          connection.query(
            "INSERT INTO blog_sections (blog_id, heading, content) VALUES ?",
            [sectionValues],
            (err) => {
              if (err) {
                console.error(err);
                return res
                  .status(500)
                  .json({ error: "Failed to insert sections" });
              }

              res.status(200).json({
                message: "Blog and sections added successfully",
                blogId: blogId,
              });
            }
          );
        }
      );
    }
  );
});

const sendReminderEmails = async () => {
  const query =
    "SELECT id, name, email, plan,phone, updated_at FROM users WHERE invoice_status = 'paid'";

  connection.query(query, async (err, users) => {
    if (err) {
      console.error("DB error:", err);
      return;
    }

    const today = new Date();
    today.setHours(0, 0, 0, 0); // remove time component

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const upcomingPayments = [];

    for (const user of users) {
      const { name, email, plan, updated_at, phone } = user;
      const startDate = new Date(updated_at);
      startDate.setHours(0, 0, 0, 0); // remove time component from updated_at

      const endDate = new Date(startDate);

      // Calculate end date based on plan
      if (plan.includes("Monthly")) {
        endDate.setMonth(endDate.getMonth() + 1);
      } else if (plan.includes("6-Month")) {
        endDate.setMonth(endDate.getMonth() + 6);
      } else if (plan.includes("Yearly")) {
        endDate.setFullYear(endDate.getFullYear() + 1);
      }

      // Check if reminder needs to be sent (2 days before the end date)
      const diffInTime = endDate.getTime() - today.getTime();
      const diffInDays = diffInTime / (1000 * 3600 * 24);

      if (diffInDays === 2) {
        // Store user info for summary email
        upcomingPayments.push({
          name,
          email,
          plan,
          dueDate: endDate.toDateString(),
          phone,
        });

        // Send reminder email to user
        const subject = "⏰ Subscription Renewal Reminder";
        const html = `
          <h3>Hi ${name},</h3>
          <p>This is a friendly reminder that your subscription is ending on <strong>${endDate.toDateString()}</strong>.</p>
          <p>To avoid service interruption, please renew your plan in time.</p>
          <p>Thanks,<br/>America IPTV</p>
        `;

        try {
          const info = await transporter.sendMail({
            from: `"America IPTV" <${process.env.EMAIL_USER}>`,
            to: email,
            subject,
            html,
          });
          console.log(`Reminder sent to ${email} | ${info.response}`);
        } catch (emailErr) {
          console.error(`Failed to send reminder to ${email}:`, emailErr);
        }
      }
    }

    // Now send summary email to yourself
    if (upcomingPayments.length > 0) {
      const summaryHtml = `
        <h2>📅 Upcoming Payments in 2 Days</h2>
        <ul>
          ${upcomingPayments
            .map(
              (u) =>
                `<li><strong>Name:</strong> ${u.name}<br/>
                     <strong>Email:</strong> ${u.email}<br/>
                     <strong>Plan:</strong> ${u.plan}<br/>
                     <strong>Due Date:</strong> ${u.dueDate}<br/>
                     <strong>Phone no:</strong> ${u.phone}</li><br/>`
            )
            .join("")}
        </ul>
      `;

      try {
        const summaryInfo = await transporter.sendMail({
          from: `"America IPTV" <${process.env.EMAIL_USER}>`,
          to: process.env.EMAIL_USER, // send to yourself
          subject: "🔔 Reminder: Upcoming Subscription Payments (in 2 days)",
          html: summaryHtml,
        });
        console.log(`Summary email sent to self | ${summaryInfo.response}`);
      } catch (summaryErr) {
        console.error("Failed to send summary email to self:", summaryErr);
      }
    }
  });
};
// Schedule the function to run every day at 9:00 AM
cron.schedule("0 9 * * *", () => {
  sendReminderEmails();
});

// === START SERVER ===

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
