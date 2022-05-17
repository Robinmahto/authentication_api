import dotenv from 'dotenv';
dotenv.config();
import express from 'express';
import cors from 'cors';
import connectDB from './config/connectdb.js';
import userRoutes from './routes/userRoutes.js';

const app = express();
const port = process.env.PORT;
const DATABASE_URL = process.env.DATABASE_URL;

// CORS Policy
app.use(cors());

// Database
connectDB(DATABASE_URL);

// JSON
app.use(express.json());

// Routes
app.use('/api/user', userRoutes)




// PORT
app.listen(port, ()=>{
    console.log(`server listing at http://localhost:${port}`)
});