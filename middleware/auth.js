const jwt = require('jsonwebtoken')

const GenerateToken =(email)=>{
    return jwt.sign({email},'Secret-key',{
        expiresIn:'1h'
    })
}

var Authentication = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);
    
    jwt.verify(token, process.env.ACCESS_TOKEN, (err, decoded) => {
        if (err) {
            console.error('Error verifying token:', err);
            return res.sendStatus(403); // Send forbidden status for invalid token
        }
        req.user = decoded; // Attach user information to request object
        next();
    });
};

module.exports ={Authentication,GenerateToken};