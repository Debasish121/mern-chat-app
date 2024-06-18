import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

const protectRoute = async(req, res, next) => {
    try {
        const token = req.cookies.jwt;

        // Check if the token exist
        if(!token){
            return res.status(401).json({error : "Unauthorized - No Token Provided"})
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET)

        if(!decoded){
            return res.status(401).json({error : "Unauthorized - Invalid Token"})
        }

        const user = await User.findById(decoded.userId).select("-password");

        if(!user){
            return res.status(404).json({error : "User not found"})
        }

        req.user = user;

        next(); // call the next function i.e. sendMessage in message.route.js
    } catch (error) {
        console.log("Error in protectedRoute middleware: ", error.message)
        res.status(500).json({error : "Internal Server Error"})
    }
}

export default protectRoute;