const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const crypto = require('crypto');
const multer = require("multer");
const https = require('https');
const AWS = require('aws-sdk');
const storager2 = multer.memoryStorage();
const bcrypt = require("bcryptjs");

const uploadr2 = multer({ storage: storager2 }).single("file")
// Configure AWS SDK for Cloudflare R2
const s3 = new AWS.S3({
  endpoint: new AWS.Endpoint('https://339e91c277eee714bbecefdc897961c9.r2.cloudflarestorage.com'), // Replace <ACCOUNT_ID> with your Cloudflare Account ID
  accessKeyId: "849da980c45dc2c94f7273e84f894ac8",   // Ensure these are set in your environment
  secretAccessKey: "5f544badf3425922c5326c6dec89fb341c44ce620093481af26e443a3d74e310",
  region: 'auto',
  signatureVersion: 'v4',
});
const app = express();
const port = 4000;
const cors = require('cors');
app.use(cors());

app.use(bodyParser.urlencoded({extended: false}));
app.use(bodyParser.json());

const jwt = require('jsonwebtoken');

mongoose
  .connect('mongodb+srv://wissamardah97:HUf3Kh9dhXVJq8uU@cluster0.egwnq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch(error => {
    console.log('Error connecting to MongoDB' , error);
  });

app.listen(port, () => {
  console.log('Server is running on port 4000');
});

const User = require('./models/user');
const Message = require('./models/message');

app.post("/uploadr3", function (req, res) {

  console.log("test")
});
app.post("/uploadr2", function (req, res) {
  
  console.log("test")
  uploadr2(req, res, async function (err) {
    if (err instanceof multer.MulterError) {
      // A Multer error occurred when uploading.
      console.log(err);

      res.status(500).json(err);
    } else if (err) {
      // An unknown error occurred when uploading.
      console.log(err);
      res.status(500).json(err);
    } else {
      try {
        if (!req.file) {
          return res.status(400).json({ error: 'No file uploaded' });
        }
        console.log("************")
        const timestamp = Date.now(); // Current timestamp
        const randomString = Math.random().toString(36).substring(2, 8); // Random alphanumeric string
        const fileExtension = req.file.originalname.split('.').pop(); // Extract the file extension
        const baseFileName = req.file.originalname.replace(/\.[^/.]+$/, ""); // Remove the extension
        const uniqueFileName = `${baseFileName}-${timestamp}-${randomString}.${fileExtension}`;        // Define parameters for the R2 upload
       
        console.log("************")

        const params = {
          Bucket: 'chat',  // Replace with your R2 bucket name
          Key: uniqueFileName,      // Use the original file name as the key
          Body: req.file.buffer,           // Use buffer from the in-memory storage
          ContentType: req.file.mimetype,  // Set content type
        };
    
        // Upload the file to R2
        const data = await s3.upload(params).promise();
        const publicUrl = `https://pub-7861616eb2b546fe800e1382e5be40f8.r2.dev/${params.Key}`;
        // Respond with the R2 file URL
        res.status(200).json({ url: publicUrl, name: req.file.originalname,filePath:params.Key });
      } catch (err) {
        console.error('Error uploading to R2:', err);
    
        if (err instanceof multer.MulterError) {
          // Multer-specific error
          res.status(500).json({ error: err.message });
        } else {
          // Other errors
          res.status(500).json({ error: 'Failed to upload file' });
        }
      }
    }
  });
});
app.post('/register', async (req, res) => {
  const {name, email, password, image,publickey} = req.body;
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      return res.status(500).send({
        msg: err,
      });
    } else {
      const newUser = new User({name, email, password:hash, image,publickey});

      newUser
        .save()
        .then(() => {
          res.status(200).json({message: 'User registered succesfully!'});
        })
        .catch(error => {
          console.log('Error creating a user',error);
          res.status(500).json({message: 'Error registering the user'});
        });    }
  });

});

app.post('/login', async (req, res) => {
  try {
    const {email, password} = req.body;

    const user = await User.findOne({email});
    if (!user) {
      return res.status(401).json({message: 'Invalid email'});
    }

    bcrypt.compare(password, user.password, (bErr, bResult) => {
      if (bErr) {
        return res.status(401).json({message: 'Invalid password'});

      }

      if (bResult) {
        {
        

    const token = jwt.sign({userId: user._id,publickey:user.publickey,name:user.name,email:user.email,image:user.image,friend:user.friends}, process.env.JWT_KEY);

    res.status(200).json({token});
        }
      }

      return res.status(401).json({message: 'Invalid password'});

    });



  } catch (error) {
    console.log('error loggin in', error);
    res.status(500).json({message: 'Error loggin In'});
  }
});

// app.get('/users/:userId', async (req, res) => {
//   try {
//     const userId = req.params.userId;
//     const users = await User.find({_id: {$ne: userId}});

//     res.json(users);
//   } catch (error) {
//     console.log('Error1', error);
//   }
// });
app.get('/users/search', async (req, res) => {
  try {
    const query = req.query.q;
    if (!query) {
      return res.status(400).json({ message: 'Query parameter is required' });
    }

    const users = await User.find({
      $or: [
        { name: { $regex: query, $options: 'i' } },  // Case-insensitive search in name
        { email: { $regex: query, $options: 'i' } }, // Case-insensitive search in email
      ],
    });

    res.json(users);
  } catch (error) {
    console.error('Error1:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
app.post('/sendrequest', async (req, res) => {
  const {senderId, receiverId, message} = req.body;

  console.log(senderId);
  console.log(receiverId);
  console.log(message);

  const receiver = await User.findById(receiverId);
  if (!receiver) {
    return res.status(404).json({message: 'Receiver not found'});
  }

  receiver.requests.push({from: senderId, message});
  await receiver.save();

  res.status(200).json({message: 'Request sent succesfully'});
});

app.get('/getrequests/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    const user = await User.findById(userId).populate(
      'requests.from',
      'name email image',
    );

    if (user) {
      res.json(user.requests);
    } else {
      res.status(400);
      throw new Error('User not found');
    }
  } catch (error) {
    console.log('error', error);
  }
});
app.post('/rejectrequest', async (req, res) => {
  try {
    const { userId, requestId } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Remove the friend request from the user's requests array
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { $pull: { requests: { from: requestId } } },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: 'Request not found' });
    }

    res.status(200).json({ message: 'Request rejected successfully' });
  } catch (error) {
    console.error('Error', error);
    res.status(500).json({ message: 'Server Error' });
  }
});
app.post('/acceptrequest', async (req, res) => {
  try {
    const { userId, requestId } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Remove the friend request
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { $pull: { requests: { from: requestId } } },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: 'Request not found' });
    }

    // Use $addToSet instead of $push to ensure uniqueness
    await User.findByIdAndUpdate(userId, {
      $addToSet: { friends: requestId }, // Prevents duplicate friends
    });

    const friendUser = await User.findByIdAndUpdate(requestId, {
      $addToSet: { friends: userId }, // Ensures user is also added uniquely
    });

    if (!friendUser) {
      return res.status(404).json({ message: 'Friend not found' });
    }

    res.status(200).json({ message: 'Request accepted successfully' });
  } catch (error) {
    console.error('Error', error);
    res.status(500).json({ message: 'Server Error' });
  }
});

app.get("/user/:userId", async (req, res) => {
  try {
    const userId = req.params.userId;

    // Validate userId before querying
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid User ID" });
    }

    // Fetch user and populate friends
    const user = await User.findById(userId).populate("friends", "name email image publickey");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Fetch friends and their last messages
    const friendsWithLastMessage = await Promise.all(
      user.friends.map(async (friend) => {
        // Find the last message exchanged with this friend
        const lastMessage = await Message.findOne({
          $or: [
            { senderId: userId, receiverId: friend._id },
            { senderId: friend._id, receiverId: userId },
          ],
        })
          .sort({ timeStamp: -1 }) // Get the latest message
          .select("message messageSender timeStamp")
          .lean();

        return {
          _id: friend._id,
          name: friend.name,
          email: friend.email,
          image: friend.image,
          publickey: friend.publickey,
          lastMessage: lastMessage || null, // If no message found, return null
          lastMessageTime: lastMessage ? lastMessage.timeStamp : null, // Used for sorting
        };
      })
    );

    // Sort friends based on last message timestamp (newest first)
    friendsWithLastMessage.sort((a, b) => {
      if (!a.lastMessageTime) return 1; // Put friends with no messages at the end
      if (!b.lastMessageTime) return -1;
      return new Date(b.lastMessageTime) - new Date(a.lastMessageTime);
    });

    res.json(friendsWithLastMessage);
  } catch (error) {
    console.error("Error fetching user and messages:", error);
    res.status(500).json({ message: "Server error" });
  }
});
const http = require('http').createServer(app);

const io = require('socket.io')(http);

//{"userId" : "socket ID"}

const userSocketMap = {};

io.on('connection', socket => {
  console.log('a user is connected', socket.id);
console.log("handshake ",socket.handshake.query)
  const userId = socket.handshake.query.userId;

  console.log('userid', userId);

  if (userId !== 'undefined') {
    userSocketMap[userId] = socket.id;
  }

  console.log('user socket data', userSocketMap);

  socket.on('disconnect', () => {
    console.log('user disconnected', socket.id);
    delete userSocketMap[userId];
  });

  socket.on('sendMessage', ({senderId, receiverId, message, messageSender}) => {
    const receiverSocketId = userSocketMap[receiverId];
    const senderSocketId = userSocketMap[senderId];


    if (receiverSocketId) {
      io.to(receiverSocketId).emit('receiveMessage', {
        senderId,
        message,
        messageSender
      });
    }
    if (senderSocketId) {
      io.to(senderSocketId).emit('receiveMessage', {
        senderId,
        message,
        messageSender
      });
    }
  });
});

http.listen(3000, () => {
  console.log('Socket.IO running on port 3000');
});

app.post('/sendMessage', async (req, res) => {
  try {
    const {senderId, receiverId, message,messageSender} = req.body;

    const newMessage = new Message({
      senderId,
      receiverId,
      message,
      messageSender
    });

    await newMessage.save();

    const receiverSocketId = userSocketMap[receiverId];
    const senderSocketId = userSocketMap[senderId];

    if (receiverSocketId) {
      console.log('emitting recieveMessage event to the reciver', receiverId);
      io.to(receiverSocketId).emit('newMessage', newMessage);
    } else{
      console.log('Receiver socket ID not found');
    }
    
    if (senderSocketId) {
      io.to(senderSocketId).emit('newMessage', newMessage);
    } 

    res.status(201).json(newMessage);
  } catch (error) {
    console.log('ERROR', error);
  }
});

app.get('/messages', async (req, res) => {
  try {
    const {senderId, receiverId} = req.query;

    const messages = await Message.find({
      $or: [
        {senderId: senderId, receiverId: receiverId},
        {senderId: receiverId, receiverId: senderId},
      ],
    }).populate('senderId', '_id name');

    res.status(200).json(messages);
  } catch (error) {
    console.log('Error', error);
  }
});


module.exports = app;
