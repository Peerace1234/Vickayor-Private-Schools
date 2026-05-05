# Firebase Integration Guide for Vickayor School Management

## Overview

This guide enables automated enquiry handling, email confirmations, and CRM functionality using Firebase. Perfect for converting form submissions into actionable leads.

## What You'll Achieve

- ✅ Form submission → Firebase → Email notification (instant)
- ✅ Parent confirmation email
- ✅ Admin dashboard for enquiry tracking
- ✅ Spam protection with rate limiting
- ✅ Contact history & analytics

---

## Step 1: Firebase Setup

### 1.1 Create Firebase Project

1. Go to [console.firebase.google.com](https://console.firebase.google.com)
2. Click "Add project"
3. Name: `vickayor-school-crm`
4. Accept terms, click Create
5. Wait for project initialization

### 1.2 Enable Services

1. In Firebase Console → **Build** → **Firestore Database**
   - Create database
   - Start in **Production mode**
   - Select region: `Africa (South Africa)` or closest to Nigeria
   - Click Enable

2. **Enable Authentication**
   - Go to **Build** → **Authentication**
   - Click "Get Started"
   - Select **Email/Password** method
   - Enable

3. **Enable Cloud Functions**
   - Go to **Build** → **Functions**
   - Click "Get Started"
   - Follow setup (will ask you to upgrade to paid plan for outgoing requests)

4. **Enable Cloud Storage** (for file uploads)
   - Go to **Build** → **Storage**
   - Create Storage → Choose `Africa (South Africa)`

---

## Step 2: Firestore Database Structure

### Create Collections and Documents

**Collection: `enquiries`**

```json
{
  "id": "auto-generated",
  "name": "String",
  "email": "String",
  "phone": "String",
  "subject": "String",
  "message": "String",
  "enquiry_type": "admission|visit|general|other",
  "status": "new|read|responded|closed",
  "parent_name": "String (optional)",
  "child_name": "String (optional)",
  "child_class": "String (optional)",
  "ip_address": "String",
  "created_at": "Timestamp",
  "updated_at": "Timestamp",
  "response": "String (optional)",
  "responded_by": "String (optional)"
}
```

**Collection: `testimonials`**

```json
{
  "id": "auto-generated",
  "author_name": "String",
  "author_role": "parent|student|staff",
  "title": "String",
  "content": "String",
  "rating": "Number (1-5)",
  "is_approved": "Boolean",
  "is_featured": "Boolean",
  "created_at": "Timestamp"
}
```

**Collection: `school_settings`**

```json
{
  "key": "school_email",
  "value": "vickayorprivateschool@gmail.com"
},
{
  "key": "whatsapp_number",
  "value": "+2347065950300"
},
{
  "key": "smtp_config",
  "value": "JSON object with email settings"
}
```

---

## Step 3: Cloud Functions for Email Automation

### 3.1 Initialize Cloud Functions Locally

```bash
# Install Firebase CLI
npm install -g firebase-tools

# Login
firebase login

# Initialize in your project folder
firebase init functions

# Choose: Use JavaScript, Yes to dependencies
```

### 3.2 Create Enquiry Email Function

**File: `functions/index.js`**

```javascript
const functions = require("firebase-functions");
const admin = require("firebase-admin");
const nodemailer = require("nodemailer");

admin.initializeApp();

// Configure your email transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// Function 1: Send confirmation email to parent + notification to school
exports.onEnquirySubmitted = functions.firestore
  .document("enquiries/{enquiryId}")
  .onCreate(async (snap, context) => {
    const enquiry = snap.data();
    const enquiryId = context.params.enquiryId;

    // Skip if already processed
    if (enquiry.processed) return;

    try {
      // Email to parent
      const parentMailOptions = {
        from: process.env.SMTP_USER,
        to: enquiry.email,
        subject: "🎓 Vickayor Private School - Enquiry Received",
        html: `
          <div style="font-family: Poppins, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #B8860B;">Vickayor Private School</h2>
            <h3>We Received Your Enquiry</h3>
            <p>Hello ${enquiry.name},</p>
            <p>Thank you for contacting Vickayor Private School. We're excited about the opportunity to serve your family.</p>
            
            <div style="background: #f5f5f5; padding: 15px; border-radius: 8px; margin: 20px 0;">
              <h4>Your Enquiry Details</h4>
              <p><strong>Subject:</strong> ${enquiry.subject}</p>
              <p><strong>Type:</strong> ${enquiry.enquiry_type}</p>
              <p><strong>Phone:</strong> ${enquiry.phone || "Not provided"}</p>
            </div>

            <p>Our admissions team will review your enquiry and get back to you within <strong>24 hours</strong> via email or phone.</p>
            
            <p><strong>In the meantime:</strong></p>
            <ul>
              <li>📖 Learn more about our programs: <a href="https://vickayor.com/academics">Visit Academics</a></li>
              <li>🎓 Check admissions details: <a href="https://vickayor.com/admissions">Admissions Page</a></li>
              <li>💬 Chat with us: <a href="https://wa.me/2347065950300">WhatsApp</a></li>
            </ul>

            <p>Warm regards,<br><strong>Vickayor Private School</strong><br>
            📞 +234 706 595 0300<br>
            📧 vickayorprivateschool@gmail.com</p>
          </div>
        `,
      };

      // Email to school admin
      const adminMailOptions = {
        from: process.env.SMTP_USER,
        to: "vickayorprivateschool@gmail.com",
        subject: `🔔 New Enquiry from ${enquiry.name} - ${enquiry.enquiry_type.toUpperCase()}`,
        html: `
          <div style="font-family: Poppins, sans-serif;">
            <h2>New Enquiry Received</h2>
            
            <div style="background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107;">
              <p><strong>Priority:</strong> ${enquiry.enquiry_type === "admission" ? "🔴 HIGH" : "🟡 NORMAL"}</p>
            </div>

            <h3>Enquiry Details</h3>
            <table style="width: 100%; border-collapse: collapse;">
              <tr style="border-bottom: 1px solid #ddd;">
                <td style="padding: 10px;"><strong>Name:</strong></td>
                <td style="padding: 10px;">${enquiry.name}</td>
              </tr>
              <tr style="border-bottom: 1px solid #ddd;">
                <td style="padding: 10px;"><strong>Email:</strong></td>
                <td style="padding: 10px;"><a href="mailto:${enquiry.email}">${enquiry.email}</a></td>
              </tr>
              <tr style="border-bottom: 1px solid #ddd;">
                <td style="padding: 10px;"><strong>Phone:</strong></td>
                <td style="padding: 10px;"><a href="tel:${enquiry.phone}">${enquiry.phone}</a></td>
              </tr>
              <tr style="border-bottom: 1px solid #ddd;">
                <td style="padding: 10px;"><strong>Type:</strong></td>
                <td style="padding: 10px;"><strong>${enquiry.enquiry_type}</strong></td>
              </tr>
              <tr style="border-bottom: 1px solid #ddd;">
                <td style="padding: 10px;"><strong>Subject:</strong></td>
                <td style="padding: 10px;">${enquiry.subject}</td>
              </tr>
              ${
                enquiry.parent_name
                  ? `
              <tr style="border-bottom: 1px solid #ddd;">
                <td style="padding: 10px;"><strong>Child:</strong></td>
                <td style="padding: 10px;">${enquiry.child_name} (${enquiry.child_class})</td>
              </tr>
              `
                  : ""
              }
            </table>

            <h4>Message</h4>
            <p style="background: #f9f9f9; padding: 15px; border-radius: 5px; white-space: pre-wrap;">${enquiry.message}</p>

            <p style="margin-top: 20px;">
              <a href="https://console.firebase.google.com/project/vickayor-school-crm/firestore/data/enquiries/${enquiry.id || ""}" 
                 style="background: #B8860B; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                View in Dashboard
              </a>
            </p>
          </div>
        `,
      };

      // Send both emails
      await transporter.sendMail(parentMailOptions);
      await transporter.sendMail(adminMailOptions);

      // Mark as processed
      await snap.ref.update({ processed: true });
      console.log("Emails sent successfully for enquiry:", enquiryId);
    } catch (error) {
      console.error("Error sending emails:", error);
    }
  });

// Function 2: Spam protection - rate limiting
exports.checkSpamSubmissions = functions.https.onCall(async (data, context) => {
  const email = data.email;
  const now = admin.firestore.Timestamp.now();
  const oneHourAgo = new Date(now.toMillis() - 60 * 60 * 1000);

  try {
    const recentSubmissions = await admin
      .firestore()
      .collection("enquiries")
      .where("email", "==", email)
      .where("created_at", ">=", oneHourAgo)
      .get();

    if (recentSubmissions.size >= 3) {
      return {
        allowed: false,
        message: "Too many submissions. Please try again later.",
      };
    }

    return { allowed: true };
  } catch (error) {
    console.error("Spam check error:", error);
    return { allowed: true }; // Allow on error
  }
});
```

### 3.3 Deploy Functions

```bash
# Set environment variables
firebase functions:config:set \
  smtp.user="your-gmail@gmail.com" \
  smtp.pass="your-gmail-app-password"

# Deploy
firebase deploy --only functions
```

---

## Step 4: Update Frontend

### Enhanced Contact Form

Replace your current contact.html with:

```html
<!-- In files/contact-firebase.html -->
<form id="enquiry-form" onsubmit="submitEnquiry(event)">
  <input type="text" id="name" placeholder="Full Name" required />
  <input type="email" id="email" placeholder="Email" required />
  <input type="tel" id="phone" placeholder="Phone Number" required />
  <select id="enquiry-type">
    <option value="general">General Enquiry</option>
    <option value="admission">Admission</option>
    <option value="visit">Campus Visit</option>
    <option value="other">Other</option>
  </select>
  <input type="text" id="subject" placeholder="Subject" required />
  <textarea
    id="message"
    placeholder="Your message"
    rows="5"
    required
  ></textarea>
  <button type="submit">Send Enquiry</button>
  <div id="status-message"></div>
</form>

<script src="https://www.gstatic.com/firebasejs/10.0.0/firebase-app.js"></script>
<script src="https://www.gstatic.com/firebasejs/10.0.0/firebase-firestore.js"></script>
<script src="https://www.gstatic.com/firebasejs/10.0.0/firebase-functions.js"></script>

<script>
  const firebaseConfig = {
    apiKey: "YOUR_API_KEY",
    authDomain: "vickayor-school-crm.firebaseapp.com",
    projectId: "vickayor-school-crm",
    storageBucket: "vickayor-school-crm.appspot.com",
    messagingSenderId: "YOUR_SENDER_ID",
    appId: "YOUR_APP_ID",
  };

  firebase.initializeApp(firebaseConfig);
  const db = firebase.firestore();
  const functions = firebase.functions();

  async function submitEnquiry(event) {
    event.preventDefault();
    const statusDiv = document.getElementById("status-message");

    try {
      const email = document.getElementById("email").value;

      // Check spam
      const checkSpam = functions.httpsCallable("checkSpamSubmissions");
      const spamResult = await checkSpam({ email });

      if (!spamResult.data.allowed) {
        statusDiv.textContent = spamResult.data.message;
        statusDiv.style.color = "red";
        return;
      }

      // Submit enquiry
      await db.collection("enquiries").add({
        name: document.getElementById("name").value,
        email: email,
        phone: document.getElementById("phone").value,
        enquiry_type: document.getElementById("enquiry-type").value,
        subject: document.getElementById("subject").value,
        message: document.getElementById("message").value,
        status: "new",
        ip_address: await getClientIP(),
        created_at: firebase.firestore.FieldValue.serverTimestamp(),
        updated_at: firebase.firestore.FieldValue.serverTimestamp(),
      });

      statusDiv.textContent =
        "✅ Enquiry sent! Check your email for confirmation.";
      statusDiv.style.color = "green";
      event.target.reset();
    } catch (error) {
      console.error("Error:", error);
      statusDiv.textContent = "❌ Error sending enquiry. Please try again.";
      statusDiv.style.color = "red";
    }
  }

  async function getClientIP() {
    try {
      const response = await fetch("https://api.ipify.org?format=json");
      const data = await response.json();
      return data.ip;
    } catch {
      return "unknown";
    }
  }
</script>
```

---

## Step 5: Create Admin Dashboard (Optional but Recommended)

### Simple Firebase Dashboard Features:

1. **Enquiry List** - See all enquiries with filters
2. **Status Management** - Mark as read, responded, closed
3. **Quick Reply** - Send template responses
4. **Analytics** - Enquiry trends, conversion rates

Use **Firebase Hosting** + **React/Vue** for dashboard, or use third-party solutions:

- [Nocobase](https://nocobase.com/) - Open-source Airtable alternative
- [Retool](https://retool.com/) - Low-code admin panels
- [Budibase](https://budibase.com/) - Open-source

---

## Step 6: Email Configuration Best Practices

### Use Gmail with App Passwords

1. Enable 2FA on your Google account
2. Create [App Password](https://myaccount.google.com/apppasswords)
3. Use app password in Firebase config (NOT your regular password)

### Alternative: Use SendGrid

```javascript
const sgMail = require("@sendgrid/mail");
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

await sgMail.send({
  to: email,
  from: "admissions@vickayorprivateschool.com",
  subject: "🎓 Vickayor - Enquiry Received",
  html: emailTemplate,
});
```

---

## Step 7: Monitoring & Maintenance

### Setup Alerts

1. Firebase Console → Firestore → Indexes
2. Monitor write operations (free tier: 50K reads/day)
3. Set up email alerts for high volume

### Regular Backups

```bash
# Backup Firestore
firebase firestore:export gs://vickayor-school-crm.appspot.com/backups/$(date +%Y%m%d)
```

---

## Troubleshooting

| Problem              | Solution                                                       |
| -------------------- | -------------------------------------------------------------- |
| Emails not sending   | Check SMTP credentials, enable Less Secure Apps if using Gmail |
| High costs           | Optimize queries, use document caching, implement pagination   |
| Slow form submission | Add loading spinner, optimize function code                    |
| Spam submissions     | Implement rate limiting, add CAPTCHA                           |

---

## Migration from Current System

### Step 1: Migrate existing enquiries.json to Firestore

```bash
node migrate-enquiries.js
```

### Step 2: Test with dummy submissions

### Step 3: Switch forms to Firebase gradually

### Step 4: Archive old enquiries.json after verification

---

## Cost Estimation (Firebase Blaze Plan - Pay as you go)

| Operation                         | Cost               |
| --------------------------------- | ------------------ |
| 10K enquiries/month               | ~$0.06             |
| Email sends (via Cloud Functions) | ~$0.07/1000 emails |
| Total estimated monthly cost      | **$2-5 USD**       |

---

## Next Steps

1. ✅ Create Firebase project
2. ✅ Deploy Cloud Functions
3. ✅ Update contact form
4. ✅ Test with sample submissions
5. ✅ Monitor and optimize
6. ✅ Build admin dashboard
7. ✅ Train staff on system

For questions or support: **Firebase documentation** or contact your Firebase support team.
