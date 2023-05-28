import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/user.js';
import mongoose from 'mongoose';

export const signin = async(req,res)=>{
          const {email,password} = req.body;
          try{
                    const existinguser = await User.findOne({email});

                    if (!existinguser) return res.status(404).json({message:"user doesnt exist"});

                    const isPasswordCorrect = await bcrypt.compare(password,existinguser.password);

                    if (!isPasswordCorrect) return res.status(404).json({message:"invalid credentials"});

                    const token = jwt.sign({email:existinguser.email,id:existinguser._id},"test",{expiresIn:"1h"});
                    res.status(200).json({result:existinguser,token});
          }catch(error){
                    res.status(500).json({message:"Something went wrong "});

          }
}

export const signup = async(req,res)=>{
          const {name,email,password,profileImage} = req.body
          try{
                    const existinguser = await User.findOne({email});

                    if (existinguser) return res.status(400).json({message:"user already exist"});

                    // if (password !== confirmPassword) return res.status(404).json({message:"passwords do not match"});

                    const hashPassword = await bcrypt.hash(password,12);

                    const result = await User.create({email,password:hashPassword,name,profileImage});

                    const token = jwt.sign({email:result.email,id:result._id},"test",{expiresIn:"1h"});

                    res.status(200).json({result,token});

          }catch(error){
                    res.status(500).json({message:"Something went wrong "});
          }
}