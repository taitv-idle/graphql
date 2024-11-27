const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const multer = require('multer');
const {graphqlHTTP} = require('express-graphql');
const graphqlSchema = require('./graphql/schema');
const graphqlResolvers = require('./graphql/resolvers');
const auth = require('./middleware/auth');
const { clearImage } = require('./util/file');
const app = express();

const fileStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'images');
    },
    filename: (req, file, cb) => {
        cb(null, new Date().toISOString() + '-' + file.originalname);
    }
});

const fileFilter = (req, file, cb) => {
    if (
        file.mimetype === 'image/png' ||
        file.mimetype === 'image/jpg' ||
        file.mimetype === 'image/jpeg'
    ) {
        cb(null, true);
    } else {
        cb(null, false);
    }
};

// app.use(bodyParser.urlencoded()); // x-www-form-urlencoded <form>
app.use(bodyParser.json()); // application/json
app.use(multer({ storage: fileStorage, fileFilter: fileFilter }).single('image'));
app.use('/images', express.static(path.join(__dirname, 'images')));

app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    // Trả về cho các yêu cầu preflight
    if (req.method === 'OPTIONS') {
        return res.status(200).end(); // Trả về ngay khi nhận yêu cầu OPTIONS
    }
    next();
});
app.use(auth);

app.put('/post-image', (req, res, next) => {
    if (!req.isAuth){
        throw new Error('Not authorized');
    }

    if (!req.file) {
        return res.status(200).json({message: 'No file provided'});
    }
    if (req.body.oldPath){
        clearImage(req.body.oldPath);
    }
    return res.status(201).json({message: 'File Stored', filePath: req.file.path});
});

app.use('/graphql',
    graphqlHTTP({
        schema: graphqlSchema,
        rootValue: graphqlResolvers,
        graphiql: true,
        customFormatErrorFn(err){
            if (!err.originalError){
                return err;
            }
            const data = err.originalError.data;
            const message = err.message || 'An error occurred.';
            const code = err.originalError.code || 500;
            return { message: message, status: code, data: data };
        }
    })
);

app.use((error, req, res, next) => {
    console.error(error);
    const status = error.statusCode || 500;
    const message = error.message;
    const data = error.data;
    res.status(status).json({ message: message, data: data });
});

const startServer = async () => {
    try {
        // Sử dụng async/await để kết nối tới MongoDB
        await mongoose.connect(
            'mongodb+srv://tester:faaJ8OzQ29fMHAIz@cluster0.maq21.mongodb.net/feeds?retryWrites=true&w=majority&appName=Cluster0'
        );
        // Sau khi kết nối thành công, bắt đầu lắng nghe yêu cầu
        const server = app.listen(8080, () => {
            console.log('Server is running on port 8080');
        });
    } catch (err) {
        console.log('Failed to connect to MongoDB:', err);
    }
};

// Gọi hàm để khởi động server
startServer();
