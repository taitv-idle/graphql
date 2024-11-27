const bcrypt = require('bcryptjs');
const validator = require('validator');
const jwt = require('jsonwebtoken');
const { clearImage } = require('../util/file');

const User = require('../models/user');
const Post = require('../models/post');

module.exports = {
    createUser: async function({ userInput }, req) {
        try {
            const errors = [];
            if (!validator.isEmail(userInput.email)) {
                errors.push({message: 'Invalid email address.' });
            }
            if (validator.isEmpty(userInput.password) ||
                !validator.isLength(userInput.password, {min: 5})) {
                errors.push({message: 'Password too short!' });
            }
            if (errors.length > 0) {
                const error = new Error('Invalid input');
                error.data = errors;
                errors.code = 422;
                throw error;
            }

            // Kiểm tra nếu người dùng đã tồn tại
            const existingUser = await User.findOne({ email: userInput.email });
            if (existingUser) {
                const error = new Error('User already exists!');
                error.code = 422; // Đặt mã lỗi là 422 (Unprocessable Entity)
                throw error;
            }

            // Mã hóa mật khẩu
            const hashedPw = await bcrypt.hash(userInput.password, 12);
            const user = new User({
                email: userInput.email,
                password: hashedPw,
                name: userInput.name,
            });

            // Lưu người dùng mới vào cơ sở dữ liệu
            const createdUser = await user.save();

            // Trả về thông tin người dùng
            return {
                ...createdUser._doc, _id: createdUser._id.toString()
            };
        } catch (err) {
            // Xử lý lỗi nếu có
            console.error(err);
            throw err;
        }
    },
    login: async function({ email, password }) {
        try {
            // Tìm người dùng trong cơ sở dữ liệu theo email
            const user = await User.findOne({ email: email });
            if (!user) {
                const error = new Error('User not found!');
                error.code = 401;
                throw error;
            }

            // So sánh mật khẩu đã mã hóa
            const isEqual = await bcrypt.compare(password, user.password);

            if (!isEqual) {
                const error = new Error('Passwords incorrect!');
                error.code = 401;
                throw error;
            }

            // Tạo token JWT
            const token = jwt.sign(
                {
                    userId: user._id.toString(),
                    email: user.email,
                },
                'truongvantai',
                { expiresIn: '2h' }
            );

            return { token: token, userId: user._id.toString() };
        } catch (err) {
            console.error(err);
            throw err;
        }
    },
    createPost: async function({ postInput }, req) {
        try{
            if (!req.isAuth) {
                const error = new Error('Not authenticated!');
                error.code = 401;
                throw error;
            }
            const errors = [];
            if (validator.isEmpty(postInput.title) ||
                !validator.isLength(postInput.title, {min: 5})) {
                errors.push({message: 'Invalid title!'});
            }
            if (validator.isEmpty(postInput.content) ||
                !validator.isLength(postInput.content, {min: 5})) {
                errors.push({message: 'Invalid content!'});
            }
            if (errors.length > 0) {
                const error = new Error('Invalid input');
                error.data = errors;
                errors.code = 422;
                throw error;
            }

            const user = await User.findById(req.userId);
            if(!user) {
                const error = new Error('User not found!');
                error.code = 401;
                throw error;
            }

            const post = new Post({
                title : postInput.title,
                content: postInput.content,
                imageUrl: postInput.imageUrl,
                creator: user
            });

            const createdPost = await post.save();
            user.posts.push(createdPost);
            await user.save();
            return {
                ...createdPost._doc,
                _id: createdPost._id.toString(),
                createdAt:createdPost.createdAt.toISOString(),
                updatedAt:createdPost.updatedAt.toISOString()
            };
        }catch(err){
            console.error(err);
            throw err;
        }
    },
    posts: async function({page}, req) {
        try {
            if (!req.isAuth) {
                const error = new Error('Not authenticated!');
                error.code = 401;
                throw error;
            }

            if (!page){
                page = 1;
            }
            const perPage = 2;
            const totalPosts = await Post.find().countDocuments();
            const posts = await Post.find()
                .sort({ createdAt: -1 })
                .skip((page - 1) * perPage)
                .limit(perPage)
                .populate('creator');
            return {
                posts: posts.map(p => ({
                    ...p._doc,
                    _id: p._id.toString(),
                    createdAt: p.createdAt.toISOString(),
                    updatedAt: p.updatedAt.toISOString()
                })),
                totalPost: totalPosts
            };
        } catch (err) {
            console.error(err);
            throw err;
        }
    },
    post: async function ({ id }, req) {
        try {
            // Kiểm tra xem người dùng đã xác thực chưa
            if (!req.isAuth) {
                const error = new Error('Not authenticated!');
                error.code = 401;
                throw error;
            }

            // Tìm bài viết theo ID và populate thông tin người tạo
            const post = await Post.findById(id).populate('creator');
            if (!post) {
                const error = new Error('Post not found!');
                error.code = 404;
                throw error;
            }

            // Trả về bài viết với các trường đã được định dạng
            return {
                ...post._doc,
                _id: post._id.toString(),
                createdAt: post.createdAt.toISOString(),
                updatedAt: post.updatedAt.toISOString()
            };
        } catch (err) {
            // Ghi lỗi ra console và ném lỗi lên trên
            console.error(err);
            throw err;
        }
    },
    updatePost: async function ({ id, postInput }, req) {
        try {
            // Kiểm tra xác thực người dùng
            if (!req.isAuth) {
                const error = new Error('Not authenticated!'); // Lỗi khi người dùng không được xác thực
                error.code = 401; // Mã lỗi 401: Unauthorized
                throw error;
            }

            // Tìm bài viết dựa trên `id` và liên kết dữ liệu người tạo bài viết
            const post = await Post.findById(id).populate('creator');
            if (!post) {
                const error = new Error('Post not found!'); // Lỗi khi bài viết không tồn tại
                error.code = 404; // Mã lỗi 404: Not Found
                throw error;
            }

            // Kiểm tra quyền chỉnh sửa bài viết
            if (post.creator._id.toString() !== req.userId.toString()) {
                const error = new Error('User not authorized!'); // Lỗi khi người dùng không có quyền chỉnh sửa
                error.code = 403; // Mã lỗi 403: Forbidden
                throw error;
            }

            // Xác thực đầu vào của bài viết
            const errors = [];
            if (
                validator.isEmpty(postInput.title) || // Kiểm tra tiêu đề trống
                !validator.isLength(postInput.title, { min: 5 }) // Kiểm tra độ dài tối thiểu của tiêu đề
            ) {
                errors.push({ message: 'Invalid title!' }); // Lỗi tiêu đề không hợp lệ
            }
            if (
                validator.isEmpty(postInput.content) || // Kiểm tra nội dung trống
                !validator.isLength(postInput.content, { min: 5 }) // Kiểm tra độ dài tối thiểu của nội dung
            ) {
                errors.push({ message: 'Invalid content!' }); // Lỗi nội dung không hợp lệ
            }
            if (errors.length > 0) {
                const error = new Error('Invalid input'); // Lỗi khi có lỗi đầu vào
                error.data = errors; // Gắn thêm thông tin chi tiết về lỗi
                errors.code = 422; // Mã lỗi 422: Unprocessable Entity
                throw error;
            }

            // Cập nhật tiêu đề và nội dung bài viết
            post.title = postInput.title;
            post.content = postInput.content;

            // Cập nhật đường dẫn ảnh nếu có thay đổi
            if (postInput.imageUrl !== 'undefined') {
                post.imageUrl = postInput.imageUrl;
            }

            // Lưu lại bài viết sau khi chỉnh sửa
            const updatePost = await post.save();

            // Trả về bài viết đã được cập nhật, đảm bảo định dạng dữ liệu phù hợp
            return {
                ...updatePost._doc,
                _id: updatePost._id.toString(),
                createdAt: post.createdAt.toISOString(),
                updatedAt: post.updatedAt.toISOString(),
            };
        } catch (err) {
            // Ghi lỗi ra console và ném lỗi lên trên để xử lý tiếp
            console.error(err);
            throw err;
        }
    },
    deletePost: async function ({ id }, req) {
        try {
            // Kiểm tra xác thực
            if (!req.isAuth) {
                console.log("Authentication failed");
                const error = new Error('Not authenticated!');
                error.code = 401;
                throw error;
            }

            // Tìm bài viết
            const post = await Post.findById(id).populate('creator');
            if (!post) {
                const error = new Error('Post not found!');
                error.code = 404;
                throw error;
            }

            // Kiểm tra quyền sở hữu bài viết
            if (post.creator._id.toString() !== req.userId.toString()) {
                const error = new Error('User not authorized!');
                error.code = 403;
                throw error;
            }


            // Xóa hình ảnh (kiểm tra clearImage là hợp lệ)
            clearImage(post.imageUrl);

            // Xóa bài viết khỏi cơ sở dữ liệu
            await Post.findByIdAndDelete(id);

            // Cập nhật thông tin người dùng
            const user = await User.findById(req.userId);
            user.posts.pull(id);  // Xóa bài viết khỏi danh sách bài viết của người dùng
            await user.save();

            return true; // Trả về true khi thành công
        } catch (err) {
            // Ghi lỗi ra console và ném lỗi lên trên
            console.error(err);
            throw err;
        }
    },
    user: async function(args, req) {
        // Kiểm tra xác thực
        if (!req.isAuth) {
            console.log("Authentication failed");
            const error = new Error('Not authenticated!');
            error.code = 401;
            throw error;
        }

        const user = await User.findById(req.userId);
        if (!user) {
            const error = new Error('User not found!');
            error.code = 404;
            throw error;
        }

        return {...user._doc,
            _id: user._id.toString()
        };
    },
    updateStatus: async function ({ status }, req) {
        // Kiểm tra xác thực
        if (!req.isAuth) {
            console.log("Authentication failed");
            const error = new Error('Not authenticated!');
            error.code = 401;
            throw error;
        }

        const user = await User.findById(req.userId);
        if (!user) {
            const error = new Error('User not found!');
            error.code = 404;
            throw error;
        }
        user.status = status;
        await user.save();
        return {
            ...user._doc,
            _id: user._id.toString()
        }
    }

};
