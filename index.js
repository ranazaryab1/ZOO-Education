const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
/* Removed deprecated punycode module usage */
const punycode = require('punycode');
const mongoose = require('mongoose');

const app = express();
const PORT = 3000;

// MongoDB connection
mongoose.connect('mongodb+srv://zaryabrana608:Ranagg123@cluster0.46eqooe.mongodb.net/', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('Connected to MongoDB');
}).catch((err) => {
    console.error('Failed to connect to MongoDB', err);
});

// Define mongoose schemas and models
const reportSchema = new mongoose.Schema({
    // Define fields as per expected report data structure
}, { strict: false, timestamps: true });

const blogPostSchema = new mongoose.Schema({
    title: String,
    content: String,
    imageFilename: String,
    postTime: Number,
    likes: { type: Number, default: 0 },
    comments: [{
        name: String,
        text: String,
        date: { type: Date, default: Date.now }
    }]
}, { timestamps: true });

const assignmentPostSchema = new mongoose.Schema({
    program: String,
    subject: String,
    title: String,
    uploadDate: String,
    filename: String,
}, { timestamps: true });

const bookPostSchema = new mongoose.Schema({
    class: String,
    program: String,
    subject: String,
    title: String,
    filename: String,
}, { timestamps: true });

const entryTestPostSchema = new mongoose.Schema({
    class: String,
    subject: String,
    title: String,
    section: String,
    filename: String,
}, { timestamps: true });

const pastPaperPostSchema = new mongoose.Schema({
    class: String,
    subject: String,
    title: String,
    filename: String,
}, { timestamps: true });

const Report = mongoose.model('Report', reportSchema);
const BlogPost = mongoose.model('BlogPost', blogPostSchema);
const AssignmentPost = mongoose.model('AssignmentPost', assignmentPostSchema);
const BookPost = mongoose.model('BookPost', bookPostSchema);
const EntryTestPost = mongoose.model('EntryTestPost', entryTestPostSchema);
const PastPaperPost = mongoose.model('PastPaperPost', pastPaperPostSchema);

// Ensure upload directories exist
const blogUploadDir = path.join(__dirname, 'B-A-A-R', 'blog-uploads');
const assignmentUploadDir = path.join(__dirname, 'B-A-A-R', 'assignment-uploads');
const booksUploadDir = path.join(__dirname, 'Books & Notes', 'books-uploads');
const entryTestUploadDir = path.join(__dirname, 'B-A-A-R', 'entry-test-uploads');
const pastPapersUploadDir = path.join(__dirname, 'Past Papers', 'past-papers-uploads');

if (!fs.existsSync(blogUploadDir)) {
    fs.mkdirSync(blogUploadDir, { recursive: true });
}
if (!fs.existsSync(assignmentUploadDir)) {
    fs.mkdirSync(assignmentUploadDir, { recursive: true });
}
if (!fs.existsSync(booksUploadDir)) {
    fs.mkdirSync(booksUploadDir, { recursive: true });
}
if (!fs.existsSync(entryTestUploadDir)) {
    fs.mkdirSync(entryTestUploadDir, { recursive: true });
}
if (!fs.existsSync(pastPapersUploadDir)) {
    fs.mkdirSync(pastPapersUploadDir, { recursive: true });
}

// Multer storage configurations
const storageBlog = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, blogUploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const storageAssignment = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, assignmentUploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const storageBook = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, booksUploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const storageEntryTest = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, entryTestUploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const storagePastPapers = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, pastPapersUploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedMimes = ['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    const allowedExts = ['.pdf', '.docx'];
    if (allowedMimes.includes(file.mimetype) || allowedExts.includes(path.extname(file.originalname).toLowerCase())) {
        cb(null, true);
    } else {
        cb(new Error('Only PDF and DOCX files are allowed'), false);
    }
};

const uploadBlog = multer({ storage: storageBlog, fileFilter: fileFilter });
const uploadAssignment = multer({ storage: storageAssignment, fileFilter: fileFilter });
const uploadBook = multer({ storage: storageBook, fileFilter: fileFilter });
const uploadEntryTest = multer({ storage: storageEntryTest, fileFilter: fileFilter });
const uploadPastPapers = multer({ storage: storagePastPapers, fileFilter: fileFilter });

// Serve static files from root and subfolders
app.use(express.static(path.join(__dirname)));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Upload endpoint for blog files
app.post('/upload/blog', uploadBlog.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    res.json({ message: 'Blog file uploaded successfully', filename: req.file.filename });
});

// Upload endpoint for assignment files
app.post('/upload/assignment', uploadAssignment.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    res.json({ message: 'Assignment file uploaded successfully', filename: req.file.filename });
});

// Upload endpoint for book files
app.post('/upload/book', uploadBook.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    res.json({ message: 'Book file uploaded successfully', filename: req.file.filename });
});

// Upload endpoint for entry-test files
app.post('/upload/material', (req, res) => {
    uploadEntryTest.single('file')(req, res, function (err) {
        if (err instanceof multer.MulterError) {
            console.error('Multer error:', err);
            return res.status(500).json({ error: 'Multer uploading error: ' + err.message });
        } else if (err) {
            console.error('Unknown error:', err);
            return res.status(500).json({ error: 'Unknown uploading error: ' + err.message });
        }
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        res.json({ message: 'Entry test material uploaded successfully', filename: req.file.filename });
    });
});

// New API endpoint to list all relevant files
app.get('/api/all-files', (req, res) => {
    const baseDir = __dirname;
    const foldersToScan = [
        'B-A-A-R',
        'Books & Notes',
        'Past Papers',
        'Quick mcqs',
        path.join('B-A-A-R', 'blog-uploads'),
        path.join('B-A-A-R', 'assignment-uploads')
    ];

    const allFiles = [];

    foldersToScan.forEach(folder => {
        const folderPath = path.join(baseDir, folder);
        if (fs.existsSync(folderPath)) {
            const files = fs.readdirSync(folderPath);
            files.forEach(file => {
                const filePath = path.join(folderPath, file);
                const stat = fs.statSync(filePath);
                if (stat.isFile()) {
                    // For main folders, only include .html files
                    if (
                        folder === 'B-A-A-R' ||
                        folder === 'Books & Notes' ||
                        folder === 'Past Papers' ||
                        folder === 'Quick mcqs'
                    ) {
                        if (path.extname(file).toLowerCase() === '.html') {
                            allFiles.push({
                                name: file,
                                path: path.join(folder, file).replace(/\\/g, '/')
                            });
                        }
                    } else {
                        // For blog-uploads and assignment-uploads, include all files
                        allFiles.push({
                            name: file,
                            path: path.join(folder, file).replace(/\\/g, '/')
                        });
                    }
                }
            });
        }
    });

    res.json(allFiles);
});

// POST /submit-report endpoint to save report data to MongoDB
app.post('/submit-report', async (req, res) => {
    const reportData = req.body;
    console.log('Received report:', reportData);

    try {
        const report = new Report(reportData);
        await report.save();

        res.json({ message: 'Report received and saved to database successfully' });
    } catch (err) {
        console.error('Error saving report to database:', err);
        res.status(500).json({ error: 'Failed to save report to database' });
    }
});

// File paths for storing posts
const blogPostsFile = path.join(__dirname, 'B-A-A-R', 'blog-posts.json');
const assignmentPostsFile = path.join(__dirname, 'B-A-A-R', 'assignment-posts.json');

// POST /submit-blog-post endpoint to save blog post data to MongoDB
app.post('/submit-blog-post', async (req, res) => {
    const blogPostData = req.body;
    console.log('Received blog post:', blogPostData);

    try {
        const blogPost = new BlogPost(blogPostData);
        await blogPost.save();

        // Keep saving to JSON file as fallback
        const blogPosts = fs.existsSync(blogPostsFile) ? JSON.parse(fs.readFileSync(blogPostsFile, 'utf-8')) : [];
        blogPosts.unshift(blogPostData);
        fs.writeFileSync(blogPostsFile, JSON.stringify(blogPosts, null, 2), 'utf-8');

        res.json({ message: 'Blog post received and saved to database successfully' });
    } catch (err) {
        console.error('Error saving blog post to database:', err);
        res.status(500).json({ error: 'Failed to save blog post to database' });
    }
});


// GET /api/blog-posts endpoint to fetch all blog posts from MongoDB
app.get('/api/blog-posts', async (req, res) => {
    try {
        const blogPosts = await BlogPost.find();
        res.json(blogPosts);
    } catch (err) {
        console.error('Error fetching blog posts:', err);
        res.status(500).json({ error: 'Failed to fetch blog posts' });
    }
});

const { Types } = require('mongoose');

// POST /like-blog-post/:id endpoint to increment likes for a blog post
app.post('/like-blog-post/:id', async (req, res) => {
    try {
        const postId = req.params.id;
        if (!Types.ObjectId.isValid(postId)) {
            return res.status(400).json({ error: 'Invalid blog post ID' });
        }
        const updatedPost = await BlogPost.findByIdAndUpdate(
            postId,
            { $inc: { likes: 1 } },
            { new: true }
        );
        if (!updatedPost) {
            return res.status(404).json({ error: 'Blog post not found' });
        }
        res.json({ message: 'Like added successfully', likes: updatedPost.likes });
    } catch (err) {
        console.error('Error liking blog post:', err);
        res.status(500).json({ error: 'Failed to like blog post' });
    }
});

// POST /submit-assignment-post endpoint to save assignment post data to MongoDB
app.post('/submit-assignment-post', async (req, res) => {
    const assignmentPostData = req.body;
    console.log('Received assignment post:', assignmentPostData);

    try {
        const assignmentPost = new AssignmentPost(assignmentPostData);
        await assignmentPost.save();

        // Keep saving to JSON file as fallback
        const assignmentPosts = fs.existsSync(assignmentPostsFile) ? JSON.parse(fs.readFileSync(assignmentPostsFile, 'utf-8')) : [];
        assignmentPosts.unshift(assignmentPostData);
        fs.writeFileSync(assignmentPostsFile, JSON.stringify(assignmentPosts, null, 2), 'utf-8');

        res.json({ message: 'Assignment post received and saved to database successfully' });
    } catch (err) {
        console.error('Error saving assignment post to database:', err);
        res.status(500).json({ error: 'Failed to save assignment post to database' });
    }
});

// GET /api/assignment-posts endpoint to fetch all assignment posts from MongoDB
app.get('/api/assignment-posts', async (req, res) => {
    try {
        const assignmentPosts = await AssignmentPost.find();
        res.json(assignmentPosts);
    } catch (err) {
        console.error('Error fetching assignment posts:', err);
        res.status(500).json({ error: 'Failed to fetch assignment posts' });
    }
});

// POST /submit-book-post endpoint to save book post data to MongoDB
app.post('/submit-book-post', async (req, res) => {
    const bookPostData = req.body;
    console.log('Received book post:', bookPostData);

    try {
        const bookPost = new BookPost(bookPostData);
        await bookPost.save();

        res.json({ message: 'Book post received and saved to database successfully' });
    } catch (err) {
        console.error('Error saving book post to database:', err);
        res.status(500).json({ error: 'Failed to save book post to database' });
    }
});

// POST /submit-material-post endpoint to save entry-test post data to MongoDB
app.post('/submit-material-post', async (req, res) => {
    const materialPostData = req.body;
    console.log('Received material post:', materialPostData);

    try {
        const entryTestPost = new EntryTestPost(materialPostData);
        await entryTestPost.save();

        res.json({ message: 'Material post received and saved to database successfully' });
    } catch (err) {
        console.error('Error saving material post to database:', err);
        res.status(500).json({ error: 'Failed to save material post to database' });
    }
});

// GET /api/book-posts endpoint to fetch all book posts from DB
app.get('/api/book-posts', async (req, res) => {
    try {
        const bookPosts = await BookPost.find();
        res.json(bookPosts);
    } catch (err) {
        console.error('Error fetching book posts:', err);
        res.status(500).json({ error: 'Failed to fetch book posts' });
    }
});

// GET /api/entry-test-posts endpoint to fetch all entry test posts from DB
app.get('/api/entry-test-posts', async (req, res) => {
    try {
        const entryTestPosts = await EntryTestPost.find();
        res.json(entryTestPosts);
    } catch (err) {
        console.error('Error fetching entry test posts:', err);
        res.status(500).json({ error: 'Failed to fetch entry test posts' });
    }
});

// Download endpoint for book files
app.get('/download/book/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(booksUploadDir, filename);

    if (fs.existsSync(filePath)) {
        res.download(filePath);
    } else {
        res.status(404).json({ error: 'File not found' });
    }
});

// Download endpoint for entry-test files
app.get('/download/entry-test/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(entryTestUploadDir, filename);

    if (fs.existsSync(filePath)) {
        res.download(filePath);
    } else {
        res.status(404).json({ error: 'File not found' });
    }
});

// Upload endpoint for past papers files
app.post('/upload/past-paper', (req, res) => {
    uploadPastPapers.single('file')(req, res, function (err) {
        if (err instanceof multer.MulterError) {
            console.error('Multer error:', err);
            return res.status(500).json({ error: 'Multer uploading error: ' + err.message });
        } else if (err) {
            console.error('Unknown error:', err);
            return res.status(500).json({ error: 'Unknown uploading error: ' + err.message });
        }
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        res.json({ message: 'Past paper uploaded successfully', filename: req.file.filename });
    });
});

// POST /submit-past-paper-post endpoint to save past paper post data to MongoDB
app.post('/submit-past-paper-post', async (req, res) => {
    const pastPaperPostData = req.body;
    console.log('Received past paper post:', pastPaperPostData);

    try {
        const pastPaperPost = new PastPaperPost(pastPaperPostData);
        await pastPaperPost.save();

        res.json({ message: 'Past paper post received and saved to database successfully' });
    } catch (err) {
        console.error('Error saving past paper post to database:', err);
        res.status(500).json({ error: 'Failed to save past paper post to database' });
    }
});

// GET /api/past-paper-posts endpoint to fetch past paper posts from DB, optionally filtered by class
app.get('/api/past-paper-posts', async (req, res) => {
    try {
        const { class: classFilter } = req.query;
        const query = classFilter ? { class: classFilter } : {};
        const pastPaperPosts = await PastPaperPost.find(query);
        res.json(pastPaperPosts);
    } catch (err) {
        console.error('Error fetching past paper posts:', err);
        res.status(500).json({ error: 'Failed to fetch past paper posts' });
    }
});

// Download endpoint for past paper files
app.get('/download/past-paper/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(pastPapersUploadDir, filename);

    if (fs.existsSync(filePath)) {
        res.download(filePath);
    } else {
        res.status(404).json({ error: 'File not found' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
