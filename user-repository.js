import DBLocal from "db-local";
import crypto from "crypto"
import bcrypt from "bcrypt"
import dotenv from "dotenv"
dotenv.config()


const { Schema } = new DBLocal({ path: "./db" })

const User = Schema("User", {
    _id: {type: String, required: true },
    username: {type: String, required: true },
    password: {type: String, required: true },

})

export class UserRepository {
    static async create ({ username, password }) {
        //Validators
        Validation.username(username)
        Validation.password(password)

        // Username no exists

        const user = User.findOne({username})
        if(user) throw new Error("username already exists")

        const id = crypto.randomUUID()

        const hashPaswword = await bcrypt.hash(password,10)

        User.create({
            _id:id,
            username,
            password : hashPaswword
        }).save()

        return id
    }   
    static async login ({ username, password }) {
        Validation.username(username)
        Validation.password(password)
        const user = User.findOne({username})
        if (!user) throw new Error("username does not exist")

        const isValid = await bcrypt.compare(password, user.password)
        if(!isValid) throw new Error("password is invalid")
        const {password:_, ...publicUser} = user
        return publicUser   
    }
}

class Validation{
    static username (username) {
        if( typeof username !==  "string" ) throw new Error("username must be a string")
        if( username.length < 3) throw new Error("username must be at least 3 characteres long")
    }
    static password (password){
        if(typeof password !== "string")throw new Error("password must be a string")
        if(password.length < 3 ) throw new Error("password must be at least 3 characters long ")
    }
}