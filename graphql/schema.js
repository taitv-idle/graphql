const { buildSchema } = require('graphql');

module.exports = buildSchema(`
    type Post {
        _id: ID!
        title: String!
        content: String!
        imageUrl: String!
        creator: User!
        createdAt: String!
        updatedAt: String!
    }
    
    type User {
        _id: ID!
        name: String!
        email: String!
        password: String!  # Password không nên trả về trong response
        status: String!
        posts: [Post!]  # Người dùng có thể có nhiều bài viết
    }
    
    type AuthData {
        token: String!
        userId: String!
    }
    
    type PostData {
        posts: [Post!]!
        totalPost: Int!
    }
    
    input UserInputData {
        email: String!
        name: String!
        password: String!
    }
    
    input PostInputData {
        title: String!
        content: String!
        imageUrl: String!
    }
    
    type RootQuery {
        login(email: String!, password: String!): AuthData!
        posts(page: Int): PostData!
        post(id: ID!): Post!
        user: User!
    }

    type RootMutation {
        createUser(userInput: UserInputData): User!
        createPost(postInput: PostInputData): Post!
        updatePost(id: ID!, postInput: PostInputData): Post!
        deletePost(id: ID!): Boolean!
        updateStatus(status:String!): User!
    }

    schema {
        query: RootQuery
        mutation: RootMutation
    }
`);
