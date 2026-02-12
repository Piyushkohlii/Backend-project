import mongoose , {Schema} from 'mongoose'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'

const userSchema = new Schema({
    username:{
        type:String,
        required : true,
        unique : true,
        lowercase : true,
        trim:true,
        index:true
    },
    email:{
        type:String,
        required : true,
        unique : true,
        lowercase : true,
        trim:true,
    },
    fullName:{
        type:String,
        required : true,
        trim:true,
        index : true
    },
    avatar:{
        type:String, //cloudinary url to store images
        required : true,
    },
    coverImage:{
        type:String,
    },
    password:{
        type:String,
        required : [true, 'Password is required'],
    },
    refreshToken:{
        type:String,
    },
    watchHistory :[
        {
            type:Schema.Types.ObjectId,
            ref: "Video"
        }
    ]
},{timestamps:true})

userSchema.pre("save", async function(next){ //  we are not using arrow function because it is not suitable to point the object in arrow function 
    if(this.isModified("password")){
    this.password= await bcrypt.hash(this.password,10) 
    }// bcrypt.hash is used to encypt the passowrd
    next() //next will take it to next middleware if exists else to the response 
})

userSchema.methods.isPasswordCorrect = async function(password){
    return await bcrypt.compare(password , this.password) //here the password which user gave and the encrypted passowrd will be compared 
}// by using.method we can create our own custom method

userSchema.methods.generateAccessToken = function(){
    jwt.sign(
        {
            _id: this._id,
            email: this.email,
            username: this.username,
            fullName: this.fullName 
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn : process.env.ACCESS_TOKEN_EXPIRY
        }
    )
}

userSchema.methods.generateRefreshToken = function(){
    jwt.sign(
        {
            _id: this._id,
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn : process.env.REFRESH_TOKEN_SECRET
        }
    )
}

export const User = mongoose.model("User", userSchema)