// Application configuration
var API_BASE = "https://api.internal.example.com";

const config = {
    apiUrl: "/api/v1/users",
    baseURL: "https://backend.example.com/api/v2",
    awsKey: "AKIAIOSFODNN7EXAMPLE",
    googleApiKey: "AIzaSyA1234567890abcdefghijklmnopqrstuv",
};

// Slack integration
const SLACK_WEBHOOK = "https://hooks.example.com/services/TXXXXXXXX/BXXXXXXXX/xxxxxxxxxxxxxxxxxxxxxxxx";

// Stripe
const STRIPE_KEY = "sk_test_1234567890abcdefghijklmnop";

// GitHub
const GH_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";

// JWT token in code
const authToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

// Generic password
const dbConfig = {
    password: "super_secret_db_password_123",
    host: "192.168.1.100",
};

// Database URL
const mongoUri = "mongodb://admin:password123@db.internal.example.com:27017/myapp";

// API endpoints
fetch("/api/v2/admin/settings");
axios.get("/api/v1/payments/history");

// S3 bucket
const uploadBucket = "my-app-uploads.s3.amazonaws.com";

// Cloud URLs
const storageUrl = "myapp-storage.blob.core.windows.net";
const firebaseUrl = "myproject.firebaseio.com";

// Email
const supportEmail = "support@internal.example.com";

// IP addresses
const servers = ["10.0.0.1", "192.168.1.50"];

// Domain references
const domains = ["api.internal.example.com", "staging.example.com"];
