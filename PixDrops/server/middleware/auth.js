import jwt from "jsonwebtoken";

export const verifyToken = async (req, res, next) => {
    try{
        let token = req.headers.authorization;
        if (!token) return res.sendStatus(403).send("Access denied");
        if(token.startsWith("Bearer ")){
            token = token.slice(7, token.length).trimLeft();
        }
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    }
    catch(err){
        res.staus(500).json({error: err.message});
    }
}