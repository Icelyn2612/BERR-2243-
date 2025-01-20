require("dotenv").config();
const bcrypt = require("bcrypt");
const express = require("express");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet"); //HTTPS
const csurf = require("csurf"); //CSRF
const mongoSanitize = require("express-mongo-sanitize"); //Input JSON
const cookieParser = require("cookie-parser"); //JSON parser
const axios = require("axios"); //reCAPTCHA server
const router = express.Router(); //

const app = express();
const port = process.env.PORT || 3000;
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const { message } = require("statuses");
const uri = `mongodb+srv://b022210249:${process.env.MongoDb_password}@cluster0.qexjojg.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// Rate limiter for login attempts
const login_RateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message:
    "Too many login attempts from this IP, please try again after 15 minutes",
});

// Middleware setup
app.use(express.json()); // Middleware to parse JSON requests
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(cookieParser()); // Middleware to parse cookies

//Use Helmet to set security-related HTTP headers
app.use(helmet());
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "https://www.google.com",
          "https://www.gstatic.com",
        ],
        frameSrc: ["https://www.google.com"],
      },
    },
    referrerPolicy: { policy: "no-referrer" },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
    hidePoweredBy: true,
    xssFilter: false,
    noSniff: true,
  })
);

// Use Middleware express-mongo-sanitize to sanitize inputs before they are sent to the database
app.use((req, res, next) => {
  req.body = mongoSanitize(req.body);
  req.query = mongoSanitize(req.query);
  req.params = mongoSanitize(req.params);
  next();
});

// Enable CSRF protection middleware
app.use(csurf({ cookie: true }));
// Route to get CSRF token
app.get("/csrf-token", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

//API FOR ADMIN
//login for admin
app.post("/adminLogin", async (req, res) => {
  // Check if all required fields are provided
  if (!req.body.name || !req.body.email) {
    return res.status(400).send("name and email are required. ( ˘ ³˘)❤");
  }
  // Check if the admin already exists
  let resp = await client
    .db("Assignment")
    .collection("admin")
    .findOne({
      $and: [{ name: req.body.name }, { email: req.body.email }],
    });
  if (!resp) {
    res.send("Admin not found ⸨◺_◿⸩");
  } else {
    // Check if password is true
    if (resp.password) {
      if (bcrypt.compareSync(req.body.password, resp.password)) {
        //if the password is correct, send the token and message
        const token = jwt.sign(
          {
            id: resp._id,
            name: resp.name,
            email: resp.email,
            roles: resp.roles,
          },
          process.env.JWT_SECRET,
          { expiresIn: "1h" }
        );
        console.log(token);
        res.status(200).send({
          message:
            "Admin login successful. Do yer thang in the admin panel!!\n(っ＾▿＾)۶🍸🌟🍺٩(˘◡˘ )",
          token: token,
        });
      } else {
        //if the password is wrong, send the message
        res.send("Wrong Password ⸨◺_◿⸩");
      }
    } else {
      //if the password is not provided, send the message
      res.send("Password not provided ⸨◺_◿⸩");
    }
  }
});

// Admin Login API
app.post("/adminLogin2", login_RateLimiter, async (req, res) => {
  if (
    !req.body.name ||
    !req.body.email ||
    !req.body.password ||
    !req.body.g_recaptcha_response
  ) {
    return res
      .status(400)
      .send(
        "name,email,password and g_recaptcha_response are required. ( ˘ ³˘)❤"
      );
  }

  // Input Validation
  const schema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().required(),
    g_recaptcha_response: Joi.string().required(),
  });
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).send(error.details[0].message);
  }
  // Validate reCAPTCHA
  const verifyHuman = await verifyRecaptchaToken(req.body.g_recaptcha_response);
  if (!verifyHuman) {
    return res
      .status(400)
      .send("reCAPTCHA verification failed. Please try again.");
  }

  // Check if the admin already exists
  let resp = await client
    .db("Assignment")
    .collection("admin")
    .findOne({ $and: [{ name: req.body.name }, { email: req.body.email }] });
  if (!resp) {
    return res.status(400).send("Admin not found ⸨◺_◿⸩");
  }
  // Check if password is correct
  if (bcrypt.compareSync(password, resp.password)) {
    // Create JWT
    const token = jwt.sign(
      { id: resp._id, name: resp.name, email: resp.email, roles: resp.roles },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.status(200).send({
      message:
        "Admin login successful. Do ur thing in the admin panel!!\n(っ＾▿＾)۶🍸🌟🍺٩(˘◡˘ )",
      token,
    });
  } else {
    res.status(400).send("Wrong Password ⸨◺_◿⸩");
  }
});
//Add a new chest
app.post("/chests", verifyToken, async (req, res) => {
  //Check if the user is an admin
  if (req.identify.roles == "admin") {
    // Check if chest,price,characters and Max_power_level fields are provided
    if (
      !req.body.chest ||
      !req.body.price ||
      !req.body.characters ||
      !req.body.Max_power_level
    ) {
      //if not provided, send the message
      return res
        .status(400)
        .send(
          "chest,price,characters and Max_power_level are required.\n -`д´- "
        );
    }
    // Check if the chest already exists
    let existing = await client.db("Assignment").collection("chests").findOne({
      chest: req.body.chest,
    });
    //if the chest already exist, send the message
    if (existing) {
      res.status(400).send("Chest already exist ಠ_ಠ");
    } else {
      // Check if the character already exists in the characters array
      if (req.body.characters.includes(req.body.character)) {
        return res
          .status(400)
          .send("Character already in characters array ಠ_ಠ");
      }
      //if the chest does not exist, create the chest
      let chest = await client.db("Assignment").collection("chests").insertOne({
        chest: req.body.chest,
        price: req.body.price,
        characters: req.body.characters,
        Max_power_level: req.body.Max_power_level,
      });
      res.send(chest);
    }
  } else {
    //if the user is not authorised, send the message
    return res.status(401).send("You are not authorised to create a chest");
  }
});

//Add a new character
app.post("/character", verifyToken, async (req, res) => {
  // Check if the user is authorised to create a character
  if (req.identify.roles != "admin") {
    return res.status(401).send("You are not authorised to create a character");
  } else {
    // Check if all required fields are provided
    if (
      !req.body.character_name ||
      !req.body.health ||
      !req.body.attack ||
      !req.body.type ||
      !req.body.speed
    ) {
      //if not provided, send the message
      return res
        .status(400)
        .send(
          "character_name,health,attack,type and speed are required.\n ໒( ⇀ ‸ ↼ )७)"
        );
    }
    // Check if the character already exists
    let existing = await client
      .db("Assignment")
      .collection("characters")
      .findOne({
        name: req.body.character_name,
      });
    //if the character already exist, send the message
    if (existing) {
      res.status(400).send("Character already exist (╬≖_≖)");
    } else {
      //if not, insert the data into the database
      let character = await client
        .db("Assignment")
        .collection("characters")
        .insertOne({
          name: req.body.character_name,
          health: req.body.health,
          attack: req.body.attack,
          type: req.body.type,
        });
      res.send(character);
    }
  }
});

//Update a character
app.patch("/characterupdate/:charactername", verifyToken, async (req, res) => {
  //Check if the user is an admin
  if (req.identify.roles == "admin") {
    //Check if health,attack,speed and typefields are provided
    if (
      !req.body.health ||
      !req.body.attack ||
      !req.body.speed ||
      !req.body.type
    ) {
      return res
        .status(400)
        .send("health,attack,speed and type are required.（＞д＜）");
    }
    //Check if the character exists
    let existing = await client
      .db("Assignment")
      .collection("characters")
      .findOne({
        name: req.params.charactername,
      });
    //If the character does not exist, return an error
    if (!existing) {
      res.status(400).send("Character does not exist (´つヮ⊂)");
    } else {
      //Update the character data
      let character = await client
        .db("Assignment")
        .collection("characters")
        .updateOne(
          {
            name: req.params.charactername,
          },
          {
            $set: {
              health: req.body.health,
              attack: req.body.attack,
              speed: req.body.speed,
              type: req.body.type,
            },
          }
        );
      res.send(character);
    }
  } else {
    //if the user is not authorised, send the message
    res.status(403).send("You are not authorised to update this character");
  }
});

//Add character to chest
app.patch("/add_character_to_chest", verifyToken, async (req, res) => {
  //Check if the user is an admin
  if (req.identify.roles == "admin") {
    //Check if chest and character_name are provided
    if (!req.body.chest || !req.body.character_name) {
      return res
        .status(400)
        .send("chest and character_name are required. \n٩(๑ `н´๑)۶");
    }
    let result2 = await client
      .db("Assignment")
      .collection("chests")
      .findOne({ chest: req.body.chest });
    //If the chest does not exist, return an error
    if (!result2) {
      return res.status(404).send("Chest not found|･ω･｀)");
    }
    //If the character already exists in the chest, return an error
    if (result2.characters.includes(req.body.character_name)) {
      return res
        .status(400)
        .send("Character already exist in the chest |･ω･)ﾉ");
    }
    //Update to add the character in the chest
    const result = await client
      .db("Assignment")
      .collection("chests")
      .updateOne(
        { chest: req.body.chest },
        { $addToSet: { characters: req.body.character_name } }
      );
    res.send("Character added successfully ૮ ºﻌºა");
  } else {
    return res
      .status(401)
      .send("You are not authorised to add character to chest");
  }
});

//Delete character from chest
app.patch("/delete_character", verifyToken, async (req, res) => {
  //Check if the user is an admin
  if (req.identify.roles != "admin") {
    return res
      .status(401)
      .send("You are not authorised to delete this character");
  }
  //Check if chest and character_name are provided
  if (!req.body.chest || !req.body.char_name) {
    return res.status(400).send("name and char_name are required. ( ˘ ³˘)❤");
  }
  let char = await client.db("Assignment").collection("characters").find({
    name: req.body.char_name,
  });
  //check if the character exists
  if (char) {
    await client.db("Assignment").collection("characters").deleteOne({
      name: req.body.char_name,
    });
    //check if the character is in the chest
    let char_chest = await client.db("Assignment").collection("chests").find({
      chest: req.body.chest,
    });
    //If the character is in the chest, delete it
    if (char_chest) {
      await client
        .db("Assignment")
        .collection("chests")
        .updateOne(
          {
            chest: req.body.chest,
          },
          {
            $pull: {
              characters: req.body.char_name,
            },
          }
        );
      res.send("Character deleted successfully ( ˘ ³˘)❤");
    } else {
      //If the character is not in the chest, return an error
      res.status(400).send("Character in chest not found ( ˘︹˘ )");
    }
  } else {
    //If the character does not exist, return an error
    res.status(400).send("Character not found ( ˘︹˘ )");
  }
});

//Delete a chest
app.delete("/deleteChest/:chestName", verifyToken, async (req, res) => {
  //Check if the user is the admin
  if (req.identify.roles == "admin") {
    //Check if chest exists
    let existing_chest = await client
      .db("Assignment")
      .collection("chests")
      .findOne({
        chest: req.params.chestName,
      });
    if (existing_chest) {
      //Delete the chest
      let delete_req = await client
        .db("Assignment")
        .collection("chests")
        .deleteOne({
          chest: req.params.chestName,
        });
      console.log(delete_req);
      res.status(200).send("Chest deleted successfully q(≧▽≦q)");
    } else {
      //If the chest does not exist, return an error
      res.status(400).send("Chest not found ( ˘︹˘ )");
    }
  } else {
    //If the user is not an admin, return an error
    res.status(403).send("You are not authorised to delete this chest");
  }
});

//Delete the battle record of a player
app.delete(
  "/deleteBattleRecord/:player_name",
  verifyToken,
  async (req, res) => {
    //Check if the user is the admin
    if (req.identify.roles == "admin") {
      //Delete the BattleRecord of the player
      let delete_req = await client
        .db("Assignment")
        .collection("battle_record")
        .deleteMany({
          "battleRecord.attacker": req.params.player_name,
        });
      console.log(delete_req);
      res.status(200).send("Battle record deleted successfully ( ˘︹˘ )");
    } else {
      //If the user is not an admin, return an error
      res
        .status(403)
        .send("You are not authorised to delete the battle record");
    }
  }
);

//API FOR USERS
//Registration account for users
app.post("/register", async (req, res) => {
  // Check if name, email and password and fields are provided
  if (
    !req.body.name ||
    !req.body.email ||
    !req.body.password ||
    !req.body.gender
  ) {
    return res //if not provided, send the message
      .status(400)
      .send("name,email,password and gender are required.\n 안돼!!!(ू˃̣̣̣̣̣̣︿˂̣̣̣̣̣̣ ू)");
  }

  // Validate the password
  if (!passwordValidation(req.body.password)) {
    return res
      .status(400)
      .send(
        "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character."
      );
  }

  // Check if the username or email already exists
  let existing =
    (await client.db("Assignment").collection("players").findOne({
      name: req.body.username,
    })) ||
    (await client.db("Assignment").collection("players").findOne({
      email: req.body.email,
    }));
  //if the username or email already exists, return an error
  if (existing) {
    res.status(400).send("username or email already exist");
  } else {
    //if not, hash the password
    const hash = bcrypt.hashSync(req.body.password, 10);
    // Find the player with the highest player_id
    const highestIdPlayer = await client
      .db("Assignment")
      .collection("players")
      .find()
      .sort({ player_id: -1 })
      .limit(1)
      .toArray();
    const highestId = highestIdPlayer[0] ? highestIdPlayer[0].player_id : 0;
    // Increment the highest player_id by 1
    const nextId = highestId + 1;
    let countNum = await client
      .db("Assignment")
      .collection("characters_of_players")
      .countDocuments();
    //insert the data into the database
    let resq = await client
      .db("Assignment")
      .collection("players")
      .insertOne({
        name: req.body.name,
        player_id: nextId,
        password: hash,
        email: req.body.email,
        gender: req.body.gender,
        //collection of the player(default character is Lillia)
        collection: {
          characterList: ["Lillia"],
          character_selected: { name: "Lillia", charId: countNum },
          charId: [countNum],
        },
        roles: "player",
        money: 0,
        points: 0,
        achievements: ["A beginner player"],
        friends: { friendList: [], sentRequests: [], needAcceptRequests: [] },
        starterPackTaken: false,
      });
    //get the character Lillia from the database
    let Lilla = await client
      .db("Assignment")
      .collection("characters")
      .aggregate([
        {
          $match: { name: "Lillia" },
        },
        {
          $project: {
            _id: 0,
            name: 1,
            health: 1,
            attack: 1,
            speed: 1,
            type: 1,
          },
        },
      ])
      .toArray();
    console.log(Lilla[0]);
    //add the character Lillia to the character of the player collection
    await client
      .db("Assignment")
      .collection("characters_of_players")
      .insertOne({ char_id: countNum, characters: Lilla[0] }, { upsert: true });
    res.send(
      "Congratulation! Your account register succesfully!\nLog in to start your battle journey! \n( ◑‿◑)ɔ┏🍟--🍔┑٩(^◡^ )"
    );
  }
});

//login for users
app.post("/userLogin", async (req, res) => {
  // Check if gmail, passd and recaptcha fields are provided
  if (!req.body.gmail || !req.body.password || !req.body.g_recaptcha_response) {
    //if not provided, return an error
    return res
      .status(400)
      .send("gmail,password and g_recaptcha_response are required. ( ˘ ³˘)❤");
  }
  // Validate reCAPTCHA
  const verifyHuman = await verifyRecaptchaToken(req.body.g_recaptcha_response);
  if (!verifyHuman) {
    return res
      .status(400)
      .send("reCAPTCHA verification failed. Please try again.");
  }
  //Check if the user is the player with the email
  let resp = await client.db("Assignment").collection("players").findOne({
    email: req.body.gmail,
  });
  await delayRandom(); //Random delay between 2 and 4 seconds for both valid and invalid responses
  if (!resp) {
    res.send("User not found ⸨◺_◿⸩");
  } else {
    // Check if password is provided
    if (resp.password) {
      if (bcrypt.compareSync(req.body.password, resp.password)) {
        //if the password is correct, send the token and message
        const token = jwt.sign(
          {
            id: resp._id,
            name: resp.name,
            player_id: resp.player_id,
            email: resp.email,
            roles: resp.roles,
          },
          process.env.JWT_SECRET,
          { expiresIn: "1h" }
        );
        console.log(token);

        res.status(200).send({
          message:
            "Login successful. Remember to gain your starter pack!\n(っ＾▿＾)۶🍸🌟🍺٩(˘◡˘ )",
          token: token,
        });
      } else {
        //if the password is incorrect, return an error
        res.send("Wrong Password ⸨◺_◿⸩");
      }
    } else {
      //if the password is not provided, return an error
      res.send("Password not provided ⸨◺_◿⸩");
    }
  }
});

//login to get startpack
app.patch("/login/starterpack", verifyToken, async (req, res) => {
  // Check if name is provided
  if (!req.body.name) {
    return res.status(400).send("name is required.☜(`o´)");
  }
  // Check if the user is authorised to take the starter pack
  if (req.identify.roles == "player" && req.identify.name == req.body.name) {
    //set the range of money taken
    const min = 1000; //minimum amount of money
    const max = 2000; //maximum amount of money
    //randomly genarate amount of money
    const newMoneyAmount = Math.floor(Math.random() * (max - min + 1)) + min;
    //update the money and starter pack taken of the user
    let user = await client
      .db("Assignment")
      .collection("players")
      .findOneAndUpdate(
        {
          $and: [
            {
              name: req.body.name,
            },
            { starterPackTaken: { $eq: false } }, //check if the starter pack is taken
          ],
        },
        { $set: { starterPackTaken: true, money: newMoneyAmount } },
        { returnOriginal: false }
      );
    if (user === null) {
      //if the starter pack is already taken, return an error
      res.status(400).send("Starter pack already taken (╯°□°）╯");
    } else {
      //if the starter pack is not taken, send the message
      res.send(
        `Total amount of RM ${newMoneyAmount} is given to player ${req.body.name}🤑🤑🤑 `
      );
    }
  } else {
    //if the user is not player, send the message
    return res
      .status(401)
      .send("You are not authorised to take the starter pack");
  }
});

//Read own profile
app.get("/readUserProfile/:player_name", verifyToken, async (req, res) => {
  // Check if the user is authorised to read the profile
  if (
    req.identify.roles == "player" &&
    req.identify.name == req.params.player_name
  ) {
    //Read the own profile of the player
    let document = await client
      .db("Assignment")
      .collection("players")
      .aggregate([
        {
          $match: { name: req.params.player_name },
        },
        {
          $project: {
            _id: 0,
            player_id: 1,
            name: 1,
            gender: 1,
            money: 1,
            collection: 1,
            points: 1,
            friends: 1,
            achievements: 1,
            notifications: 1,
          },
        },
        {
          $lookup: {
            from: "players",
            localField: "friends.friendList",
            foreignField: "player_id",
            as: "friends.friendList",
          },
        },
        {
          $lookup: {
            from: "characters_of_players",
            localField: "collection.charId",
            foreignField: "char_id",
            as: "collection.charId",
          },
        },
        {
          $lookup: {
            from: "characters_of_players",
            localField: "collection.character_selected.charId",
            foreignField: "char_id",
            as: "collection.character_selected.charId",
          },
        },
        {
          $project: {
            player_id: 1,
            name: 1,
            gender: 1,
            money: 1,
            points: 1,
            "collection.characterList": 1,
            "collection.character_selected.name": 1,
            "collection.character_selected.charId.char_id": 1,
            "collection.character_selected.charId.characters": 1,
            "collection.charId.char_id": 1,
            "collection.charId.characters": 1,
            "friends.friendList.player_id": 1,
            "friends.friendList.points": 1,
            "friends.friendList.name": 1,
            "friends.friendList.gender": 1,
            "friends.sentRequests": 1,
            "friends.needAcceptRequests": 1,
            achievements: 1,
            notifications: 1,
          },
        },
        {
          $project: {
            "collection.charId._id": 0,
          },
        },
      ])
      .toArray();
    res.send(document);
  } else {
    //If the user is not authorised to read the profile, return an error
    return res.status(401).send("You are not authorised to read this player");
  }
});

// To send a friend request to another user
app.post("/send_friend_request", verifyToken, async (req, res) => {
  // Check if requesterId and requestedId are provided
  if (!req.body.requesterId || !req.body.requestedId) {
    return res
      .status(400)
      .send("requesterId and requestedId are required. (◡́.◡̀)(^◡^ )");
  }
  //Check if the user is the player with the requesterId
  if (
    req.identify.roles == "player" &&
    req.identify.player_id == req.body.requesterId
  ) {
    // Check if requester send request to himself
    if (parseInt(req.body.requesterId) === parseInt(req.body.requestedId)) {
      return res
        .status(400)
        .send("You cannot send a friend request to yourself\n໒( ̿❍ ᴥ ̿❍)u");
    }
    // Check if both players exist
    const requester = await client
      .db("Assignment")
      .collection("players")
      .findOne({ player_id: parseInt(req.body.requesterId) });
    const requested = await client
      .db("Assignment")
      .collection("players")
      .findOne({ player_id: parseInt(req.body.requestedId) });
    if (!requester || !requested) {
      return res.status(404).send("Either players not found ૮ ⚆ﻌ⚆ა?");
    }
    // Check if requested already in friendList
    if (requester.friends.friendList.includes(requested.player_id)) {
      return res
        .status(404)
        .send("The player is already in your friend list ૮ ⚆ﻌ⚆ა?");
    }
    // Check if friend request has already been sent
    if (
      requester &&
      requester.friends &&
      requester.friends.sentRequests &&
      requester.friends.sentRequests.indexOf(parseInt(req.body.requestedId)) !==
        -1
    ) {
      return res.status(400).send("Friend request already sent");
    }
    // Send the friend request and update status for both players
    const sent = await client
      .db("Assignment")
      .collection("players")
      .updateOne(
        { player_id: parseInt(req.body.requesterId) },
        { $push: { "friends.sentRequests": parseInt(req.body.requestedId) } }
      );
    const sent2 = await client
      .db("Assignment")
      .collection("players")
      .updateOne(
        { player_id: parseInt(req.body.requestedId) },
        {
          $push: {
            "friends.needAcceptRequests": parseInt(req.body.requesterId),
          },
        }
      );
    //check if update processes of requeaster and requeasted are successful
    if (sent.modifiedCount === 0 && sent2.modifiedCount === 0) {
      //If not successful, return an error
      res.status(400).send("Failed to send friend request");
    } else {
      //If successful, return a success message
      res.send("Friend request sent! \n(っ◔◡◔)っ ♥ ᶠᵉᵉᵈ ᵐᵉ /ᐠ-ⱉ-ᐟﾉ");
    }
  } else {
    //If the user is not player, return an error
    return res
      .status(401)
      .send("You are not authorised to send this friend request");
  }
});

// To  accept a friend request from another user
app.patch("/accept_friend_request", verifyToken, async (req, res) => {
  // Check if accepterId and requesterId are provided
  if (!req.body.accepterId || !req.body.requesterId) {
    return res
      .status(400)
      .send("accepterId and requesterId are required ㅇㅅㅇ");
  }
  //Check if the user is the player with the accepterId
  if (
    req.identify.roles == "player" &&
    req.identify.player_id == req.body.accepterId
  ) {
    // Check if accepter accept request from himself
    if (parseInt(req.body.accepterId) === parseInt(req.body.requesterId)) {
      return res
        .status(400)
        .send("You cannot accept a friend request from yourself");
    }
    // Check if both players exist
    const requester = await client
      .db("Assignment")
      .collection("players")
      .findOne({ player_id: parseInt(req.body.requesterId) });
    const accepter = await client
      .db("Assignment")
      .collection("players")
      .findOne({ player_id: parseInt(req.body.accepterId) });
    if (!requester || !accepter) {
      return res.status(404).send("Either players not found (=ↀωↀ=)");
    }
    //The requester and accepter and become a friend in friendList no more in needAcceptRequests
    const accept = await client
      .db("Assignment")
      .collection("players")
      .updateOne(
        {
          player_id: parseInt(req.body.accepterId),
          "friends.needAcceptRequests": parseInt(req.body.requesterId),
        },
        {
          $pull: {
            "friends.needAcceptRequests": parseInt(req.body.requesterId),
          },
          $push: { "friends.friendList": parseInt(req.body.requesterId) },
        }
      );
    console.log(accept);
    const accept2 = await client
      .db("Assignment")
      .collection("players")
      .updateOne(
        {
          player_id: parseInt(req.body.requesterId),
          "friends.sentRequests": parseInt(req.body.accepterId),
        },
        {
          $pull: { "friends.sentRequests": parseInt(req.body.accepterId) },
          $push: { "friends.friendList": parseInt(req.body.accepterId) },
        }
      );
    console.log(accept2);
    //Check if update process of accepter and accepter are successful
    if (accept.modifiedCount === 0 && accept2.modifiedCount === 0) {
      //If not successful, return an error
      res.status(400).send("Failed to accept friend request (=ↀωↀ=)");
    } else {
      //If successful, return a success message
      console.log(accepter.friends.friendList.length);
      res.send("Friend request accepted (ﾐⓛᆽⓛﾐ)✧");
      //Check if accepter has more than 5 friends and update the achievements
      if ((accepter.friends.friendList.length = 5)) {
        await client
          .db("Assignment")
          .collection("players")
          .updateOne(
            { player_id: parseInt(req.body.accepterId) },
            { $addToSet: { achievements: "Makes more friends (=✪ᆽ✪=)" } }
          );
      }
    }
  } else {
    //If the user is not authorised to accept a friend request, return an error
    return res
      .status(401)
      .send("You are not authorised to accept this friend request");
  }
});

//Remove friend
app.patch(
  "/remove_friend/:requesterId/:friendId",
  verifyToken,
  async (req, res) => {
    //Check if the user is the player with the requesterId
    if (
      req.identify.roles == "player" &&
      req.identify.player_id == req.params.requesterId
    ) {
      // Check if the requester send request to himself
      if (parseInt(req.params.requesterId) === parseInt(req.params.friendId)) {
        return res.status(400).send("You cannot remove yourself (╯ ͠° ͟ʖ ͡°)╯┻━┻");
      }
      // Check if both players exist
      const requester = await client
        .db("Assignment")
        .collection("players")
        .findOne({ player_id: parseInt(req.params.requesterId) });
      const friend = await client
        .db("Assignment")
        .collection("players")
        .findOne({ player_id: parseInt(req.params.friendId) });
      if (!requester || !friend) {
        return res.status(404).send("Either players not found (˃̣̣̥⌓˂̣̣̥ )");
      }
      // Remove the friend from the friendList of the requester
      const remove1 = await client
        .db("Assignment")
        .collection("players")
        .updateOne(
          { player_id: parseInt(req.params.requesterId) },
          { $pull: { "friends.friendList": parseInt(req.params.friendId) } }
        );
      // Remove the requester from the friendList of the friend
      const remove2 = await client
        .db("Assignment")
        .collection("players")
        .updateOne(
          { player_id: parseInt(req.params.friendId) },
          { $pull: { "friends.friendList": parseInt(req.params.requesterId) } }
        );
      //Check if update process of requester and friend are successful
      if (remove1.modifiedCount === 0 && remove2.modifiedCount === 0) {
        //If not successful, return an error
        res.status(400).send("Failed to remove friend ╥__╥");
      } else {
        //If successful, return a success message
        res.send("Friend removed ‧º·(˚ ˃̣̣̥⌓˂̣̣̥ )‧º·");
      }
    } else {
      //If the user is not authorised to remove a friend, return an error
      return res
        .status(401)
        .send("You are not authorised to remove this friend");
    }
  }
);

//Update own profile
app.patch("/update/:name", verifyToken, async (req, res) => {
  //Check is the name,email,password and gender are provided
  if (!req.body.name || !req.body.email || !req.body.gender) {
    return res
      .status(400)
      .send("name,email,password and gender are required.\n( ˘▽˘)っ♨");
  }
  //Check if the user is the player with the name
  if (req.identify.roles == "player" && req.identify.name == req.params.name) {
    //update the player data
    let require = await client
      .db("Assignment")
      .collection("players")
      .updateOne(
        {
          name: req.params.name,
        },
        {
          $set: {
            name: req.body.name,
            email: req.body.email,
            gender: req.body.gender,
          },
        }
      );
    let result = await client
      .db("Assignment")
      .collection("players")
      .findOne({ name: req.body.name });
    console.log(require);
    if (require.modifiedCount === 0) {
      res.status(400).send("Updated failed (˃̣̣̥⌓˂̣̣̥ )");
    } else {
      const newToken = jwt.sign(
        {
          id: result._id,
          name: result.name,
          player_id: result.player_id,
          email: result.email,
          roles: result.roles,
        },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
      );
      res.send({
        message: "Profile updated successfully 🍲_(ﾟ◇ﾟ；)ノﾞ",
        token: newToken,
      });
    }
  } else {
    //If the user is not an player, return an error
    return res.status(401).send("You are not authorised to update this player");
  }
});

//Delete account
app.delete("/delete/:name", verifyToken, async (req, res) => {
  //Check if the user is the player with the name
  if (req.identify.roles == "player" && req.identify.name == req.params.name) {
    //Check if the player exists
    let existing = await client.db("Assignment").collection("players").findOne({
      name: req.params.name,
    });
    if (existing) {
      //If the player exists, delete the user account
      let delete_req = await client
        .db("Assignment")
        .collection("players")
        .deleteOne({
          name: req.params.name,
        });
      res.send(delete_req);
      console.log(req.params);
    } else {
      //If the player does not exist, return an error
      res.status(400).send("Player not found ( ˘︹˘ )");
    }
  } else {
    //If the user is not an player, return an error
    return res.status(401).send("You are not authorised to delete this player");
  }
});

//Read the chess inventory
app.get("/readchests", verifyToken, async (req, res) => {
  //Check if the user is authorised to view the chests
  if (req.identify.roles == "player" || req.identify.roles == "admin") {
    //Read the chests from the database
    const chests = await client
      .db("Assignment")
      .collection("chests")
      .aggregate([{ $project: { _id: 0, chest: 1, price: 1, characters: 1 } }])
      .toArray();
    res.send(chests);
  } else {
    //If the user is not player, return an error
    return res.status(401).send("You are not authorised to view the chests");
  }
});

//Buying a chest with money to get a character
app.patch("/buying_chest", verifyToken, async (req, res) => {
  //Check if the name,email and chest are provided
  if (!req.body.name || !req.body.email || !req.body.chest) {
    return res
      .status(400)
      .send("name,email and chest are required. ( ･ิ⌣･ิ)📦(‘∀’●)♡");
  }
  //Check if the user is the player with the name
  if (req.identify.roles == "player" || req.identify.name == req.body.name) {
    //Check if the player exists
    let player = await client
      .db("Assignment")
      .collection("players")
      .findOne({
        $and: [{ name: req.body.name }, { email: req.body.email }],
      });
    if (!player) {
      //If the player does not exist, return an error
      return res.status(400).send("User or email are wrong ༼☯﹏☯༽");
    }
    //Read the chest existance
    let chest = await client.db("Assignment").collection("chests").findOne({
      chest: req.body.chest,
    });
    // Randomly select a character from the characters array
    let character_in_chest = await client
      .db("Assignment")
      .collection("chests")
      .aggregate([
        { $match: { chest: req.body.chest } },
        { $unwind: "$characters" },
        { $sample: { size: 1 } },
        {
          $lookup: {
            from: "characters",
            localField: "characters",
            foreignField: "name",
            as: "characters",
          },
        },
      ])
      .toArray();
    console.log(player);
    console.log(character_in_chest[0]);
    console.log(character_in_chest[0].characters);
    console.log(character_in_chest[0].characters[0].name);
    console.log(chest);
    // Check if the player has enough money
    if (player.money < chest.price) {
      return res.send(
        "Not enough money to buy chest. Please compete more battles to earn more money.(இ﹏இ`｡)"
      );
    }
    // Check if chest exists
    if (chest) {
      if (
        // Check if the character already exists in the collection
        player.collection.characterList.includes(
          character_in_chest[0].characters[0].name
        )
      ) {
        //Find the character in the collection with the index and update the character's health, attack and speed
        let index = player.collection.characterList.indexOf(
          character_in_chest[0].characters[0].name
        );
        console.log(index);
        let your_char = await client
          .db("Assignment")
          .collection("characters_of_players")
          .findOneAndUpdate(
            {
              char_id: player.collection.charId[index],
            },
            {
              $inc: {
                "characters.health": 100,
                "characters.attack": 100,
                "characters.speed": 0.1,
              },
            }
          );
        console.log(your_char);
        return res.send(
          character_in_chest[0].characters[0].name +
            ` already exist in your collection, power up instead 💪🏼`
        );
      } else {
        //Update the deduction of player's money and add the character to user's collection
        let newMoney = player.money - chest.price;
        newMoney = newMoney < 0 ? 0 : newMoney; // Set newMoney to 0 if it's less than 0
        let buying = await client
          .db("Assignment")
          .collection("players")
          .updateOne(
            {
              name: req.body.name,
            },
            {
              $addToSet: {
                "collection.characterList":
                  character_in_chest[0].characters[0].name,
              },
              $set: {
                money: newMoney,
                upset: true,
              },
            }
          );
        console.log(buying);
        //Check if update process is insuccessful
        if (buying.modifiedCount === 0) {
          return res.send("Failed to buy character (☍﹏⁰)｡");
        } else {
          //Update the character's info for user in collection
          let countNum = await client
            .db("Assignment")
            .collection("characters_of_players")
            .countDocuments();
          let randomChar = await client
            .db("Assignment")
            .collection("characters")
            .aggregate([
              {
                $match: { name: character_in_chest[0].characters[0].name },
              },
              {
                $project: {
                  _id: 0,
                  name: 1,
                  health: 1,
                  attack: 1,
                  speed: 1,
                  type: 1,
                },
              },
            ])
            .toArray();
          await client
            .db("Assignment")
            .collection("players")
            .updateOne(
              {
                name: req.body.name,
              },
              {
                $addToSet: {
                  "collection.characterList":
                    character_in_chest[0].characters[0].name,
                },
                $inc: {
                  money: -chest.price,
                },
                $set: {
                  upset: true,
                },
              }
            );
          //Create the characters data for user in database
          await client
            .db("Assignment")
            .collection("characters_of_players")
            .insertOne({ char_id: countNum, characters: randomChar[0] });
          await client
            .db("Assignment")
            .collection("players")
            .updateOne(
              { name: req.body.name },
              {
                $push: {
                  "collection.charId": countNum,
                },
              },
              { upsert: true }
            );
          // Check if the player has collected 21 characters and update the achievements
          if (player.collection.characterList.length === 21) {
            await client
              .db("Assignment")
              .collection("players")
              .updateOne(
                { name: req.body.name },
                {
                  $addToSet: {
                    achievements:
                      "Congraturation!!!👑You complete all characters collection🏆",
                  },
                }
              );
          }
          return res.send(
            "Chest bought successfully🦍, you got " +
              character_in_chest[0].characters[0].name +
              " in your collection."
          );
        }
      }
    } else {
      res.send("Chest not found(T⌓T)");
    }
  } else {
    //If the user is not player, return an error
    return res.status(401).send("You are not authorised to buy a chest");
  }
});

//Update to change selected_character of a user
app.patch("/change_selected_char", verifyToken, async (req, res) => {
  //Check if the name,email and character_selected are provided
  if (!req.body.name || !req.body.email || !req.body.character_selected) {
    return res
      .status(400)
      .send("name,email and character_selected are required.（◎ー◎；）");
  }
  //Check if the user is the player with the name
  if (req.identify.roles == "player" && req.identify.name == req.body.name) {
    let player = await client
      .db("Assignment")
      .collection("players")
      .findOne({
        $and: [{ name: req.body.name }, { email: req.body.email }],
      });
    //Check if the player exists
    if (!player) {
      return res.status(404).send("Player not found 👨🏾‍❤️‍👨🏾");
    }
    //Check if the character exists in the character list
    let index = player.collection.characterList.indexOf(
      req.body.character_selected
    );
    if (index === -1) {
      return res
        .status(400)
        .send("Character not found in character list (◔ヘ◔)");
    }
    //Check if the character ID list is an array
    if (!Array.isArray(player.collection.charId)) {
      return res.status(400).send("Character ID list not found (◔ヘ◔)");
    }
    const char_id = player.collection.charId[index];
    //Check if the character ID exists in the character ID list
    let read_id = await client
      .db("Assignment")
      .collection("characters_of_players")
      .findOne({ char_id: char_id });
    if (!read_id) {
      return res.status(404).send("Character not found (◔ヘ◔)");
    }
    //Update the selected character
    let selected_char = await client
      .db("Assignment")
      .collection("players")
      .updateOne(
        { name: req.body.name },
        {
          $set: {
            "collection.character_selected.name": req.body.character_selected,
            "collection.character_selected.charId": char_id,
          },
        }
      );
    //Check if the update was insuccessful
    if (selected_char.modifiedCount === 0) {
      return res.status(400).send("Failed to change selected character (◔ヘ◔)");
    } else {
      res.send(
        "Your selected character has been changed to " +
          req.body.character_selected +
          "🐣"
      );
    }
  } else {
    //If the user is not the player, return an error
    return res
      .status(401)
      .send("You are not authorised to change the selected character");
  }
});

//To battle in game with another player
app.patch("/battle", verifyToken, async (req, res) => {
  //Check if the name and email are provided
  if (!req.body.name || !req.body.email) {
    return res.status(400).send("name and email are required. ( ˘ ³˘)❤");
  }
  //Check if the user is the player with the name
  if (req.identify.roles == "player" && req.identify.name == req.body.name) {
    //Check if the player exists
    const user = await client
      .db("Assignment")
      .collection("players")
      .findOne({
        $and: [
          {
            name: req.body.name,
            email: req.body.email,
          },
        ],
      });
    if (!user) {
      return res.status(404).send("Player not found ໒( ⊡ _ ⊡ )७");
    } else if (user.collection.character_selected === null) {
      return res.status(400).send("Character not selected. (◔_◔)🍔🍕");
    }
    //Find the attacker and defender
    let attacker = await client
      .db("Assignment")
      .collection("players")
      .aggregate([
        { $match: { name: req.body.name } },
        { $project: { _id: 0, name: 1, player_id: 1, collection: 1 } },
      ])
      .toArray();
    let defender;
    do {
      defender = await client
        .db("Assignment")
        .collection("players")
        .aggregate([
          { $match: { name: { $ne: "admin" } } },
          { $sample: { size: 1 } },
          { $project: { _id: 0, name: 1, player_id: 1, collection: 1 } },
        ])
        .toArray();
    } while (attacker[0].player_id === defender[0].player_id);
    console.log(attacker[0]);
    console.log(defender[0]);
    //Check if the attacker and defender exist
    if (!attacker[0] || !defender[0]) {
      return res.status(400).send("Player not found (●･̆⍛･̆●)");
    }

    const charId_attacker = attacker[0].collection.character_selected.charId;
    const charId_defender = defender[0].collection.character_selected.charId;
    console.log(charId_attacker);
    console.log(charId_defender);
    //Read the selected_character of the attacker and defender
    let attacker_character = await client
      .db("Assignment")
      .collection("characters_of_players")
      .findOne({ char_id: charId_attacker });

    let defender_character = await client
      .db("Assignment")
      .collection("characters_of_players")
      .findOne({ char_id: charId_defender });

    console.log(attacker_character);
    console.log(defender_character);
    let battle_round = 0;
    let newHealthDefender;
    let newHealthAttacker;
    console.log(attacker_character.characters);
    console.log(defender_character.characters);
    //Check if the attacker and defender characters exist
    if (
      attacker_character &&
      attacker_character.characters &&
      defender_character &&
      defender_character.characters
    ) {
      //Start the battle
      do {
        newHealthDefender =
          defender_character.characters.health -
          attacker_character.characters.attack *
            attacker_character.characters.speed;

        newHealthAttacker =
          attacker_character.characters.health -
          defender_character.characters.attack *
            defender_character.characters.speed;

        // Update the characters' health
        defender_character.characters.health = newHealthDefender;
        attacker_character.characters.health = newHealthAttacker;

        battle_round++;
      } while (
        defender_character.characters.health > 0 &&
        attacker_character.characters.health > 0
      );
      console.log(`Battle round: ${battle_round}`);
      console.log("Attacker health left: ", newHealthAttacker);
      console.log("Defender health left: ", newHealthDefender);
    } else {
      return res.status(400).send("Character not found(●･̆⍛･̆●)");
    }
    //Check who is the winner and loser
    let winner =
      newHealthAttacker > newHealthDefender
        ? attacker[0].name
        : defender[0].name;
    let loser =
      newHealthAttacker < newHealthDefender
        ? attacker[0].name
        : defender[0].name;
    //Check if the battle is a draw
    if (newHealthAttacker === newHealthDefender) {
      return res.send("Draw. Try attack again with your luck and brain👋≧◉ᴥ◉≦");
    } else {
      //Insert the battle record into the database
      if (battle_round > 0) {
        let battleRecord = {
          attacker: attacker[0].name,
          defender: defender[0].name,
          battleRound: battle_round,
          winner: winner,
          date: new Date(),
        };
        await client
          .db("Assignment")
          .collection("battle_record")
          .insertOne({ battleRecord });

        console.log(winner);
        console.log(loser);
        console.log(battleRecord);
        //Update the player's points, notification and money
        if (loser == attacker[0].name) {
          res.send(`Nice try, you will be better next time!≧◠ᴥ◠≦✊`);
        } else {
          res.send(
            `Congratulations, you won the battle after ${battle_round} rounds!\(≧∇≦)/`
          );
        }
        //Update the winner's points, notification and money
        await client
          .db("Assignment")
          .collection("players")
          .updateOne(
            { name: winner },
            {
              $inc: { points: 3, money: 500 },
              $set: {
                notification: `Congratulations, you won a battle!≧◠‿◠≦✌`,
              },
            },
            { upsert: true }
          );

        //Update the loser's points and notification
        await client
          .db("Assignment")
          .collection("players")
          .updateOne(
            { name: loser },
            {
              $inc: { points: -1 },
              $set: {
                notification: "You are being attacked in the game!( ˘︹˘ )",
              },
            },
            { upsert: true }
          );
        await client
          .db("Assignment")
          .collection("players")
          .updateOne(
            { name: loser, points: { $lt: 0 } },
            {
              $set: { points: 0 },
            }
          );
        //Update the player's achievements
        let playerRecord = await client
          .db("Assignment")
          .collection("players")
          .findOne({ name: winner });
        // Check if the player has won the first time
        if (
          playerRecord &&
          playerRecord.achievements &&
          !playerRecord.achievements.includes("First win")
        ) {
          // Give achievement to the player who wins the first time
          await client
            .db("Assignment")
            .collection("players")
            .updateOne(
              { name: winner },
              {
                $addToSet: {
                  achievements: "First win",
                },
              }
            );
        }
      } else {
        res.send("Battle failed 川o･-･)ﾉ");
      }
    }
  } else {
    //If the user is not an player, return an error
    return res.status(401).send("You are not authorised to battle this player");
  }
});

//Read the battle record of a player
app.get("/read_battle_record/:player_name", verifyToken, async (req, res) => {
  // Check if the player is authorised to read the battle record
  if (
    req.identify.roles == "player" &&
    req.identify.name == req.params.player_name
  ) {
    // Check if the history exists
    let history = await client
      .db("Assignment")
      .collection("battle_record")
      .find({
        $or: [
          { "battleRecord.attacker": req.params.player_name },
          { "battleRecord.defender": req.params.player_name },
        ],
      })
      .toArray();
    console.log(history);
    // Check if the history is empty
    if (history.length === 0) {
      return res
        .status(404)
        .send("No history found for this player (ﾐ〒﹏〒ﾐ)Gambateh!");
    }
    res.send(history);
  } else {
    return res
      .status(401)
      .send("You are not authorised to read the battle record of this player");
  }
});

//API FOR USERS AND DEVELOPERS
//To read profile of users and developers
app.get("/read/:player_name", verifyToken, async (req, res) => {
  // Check if the user is authorised to read the player
  if (req.identify.roles == "player" || req.identify.roles == "admin") {
    // Read the information of the player from the database
    let document = await client
      .db("Assignment")
      .collection("players")
      .aggregate([
        {
          // Find the player by name
          $match: { name: req.params.player_name },
        },
        {
          // Project only the basic field  that everyone can read
          $project: {
            _id: 0,
            player_id: 1,
            name: 1,
            gender: 1,
            "collection.characterList": 1,
            points: 1,
            "friends.friendList": 1,
            achievments: 1,
          },
        },
        {
          $lookup: {
            from: "players",
            localField: "friends.friendList",
            foreignField: "player_id",
            as: "friends.friendList",
          },
        },
        {
          $project: {
            player_id: 1,
            name: 1,
            gender: 1,
            "collection.characterList": 1,
            points: 1,
            achievments: 1,
            "friends.friendList.player_id": 1,
            "friends.friendList.name": 1,
          },
        },
        {
          $lookup: {
            from: "characters",
            localField: "collection.characterList",
            foreignField: "name",
            as: "collection.characterList",
          },
        },
        {
          $project: {
            player_id: 1,
            name: 1,
            gender: 1,
            "collection.characterList.name": 1,
            "collection.characterList.health": 1,
            "collection.characterList.attack": 1,
            "collection.characterList.speed": 1,
            "collection.characterList.type": 1,
            points: 1,
            achievments: 1,
            "friends.friendList.player_id": 1,
            "friends.friendList.name": 1,
          },
        },
      ])
      .toArray();
    res.send(document);
  } else {
    //If the user is not authorised (not admin or player) to read the profile, return an error
    return res.status(401).send("You are not authorised to read this player");
  }
});

//Read leaderboard
app.get("/leaderboard", verifyToken, async (req, res) => {
  if (req.identify.roles == "player" || req.identify.roles == "admin") {
    let leaderboard = await client
      .db("Assignment")
      .collection("players")
      .aggregate([
        {
          $sort: {
            points: -1,
          },
        },
        {
          $project: {
            _id: 0,
            name: 1,
            player_id: 1,
            gender: 1,
            points: 1,
          },
        },
      ])
      .toArray();
    if (leaderboard.length > 0) {
      // Give achievement to the top player
      await client
        .db("Assignment")
        .collection("players")
        .updateOne(
          { player_id: leaderboard[0].player_id },
          {
            $addToSet: {
              achievements: "You are the Top of King in this Game👑",
            },
          }
        );
    }
    res.send(leaderboard);
  } else {
    //If the user is not authorised (not admin or player) to read the leaderboard, return an error
    return res
      .status(401)
      .send("You are not authorised to view the leaderboard");
  }
});

app.get("/", (req, res) => {
  res.send(
    // __dirname +
    //   "/public/index.html" +
    "Welcome To My World!! ( -ω ･)▄︻┻┳══━一"
  );
  //res.send("FOR BATTLE!! GAME ( -ω ･)▄︻┻┳══━一  ");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});

// // Function to simulate time delay (in milliseconds)
// function delay(ms) {
//   return new Promise(resolve => setTimeout(resolve, ms));
// }
function delayRandom() {
  // Generate a random delay between 2 and 4 seconds (2000ms to 4000ms)
  const randomDelay = Math.floor(Math.random() * 2000) + 2000; // Random delay between 2000ms and 4000ms
  return new Promise((resolve) => setTimeout(resolve, randomDelay));
}

const recaptchaSiteKey = process.env.RECAPTCHA_SITE_KEY;
const recaptchaSecretKey = process.env.RECAPTCHA_SECRET_KEY;

// / Verify reCAPTCHA Token at Google’s reCAPTCHA and returns true if the verification is successful or false
async function verifyRecaptchaToken(token) {
  try {
    const response = await axios.post(
      `https://www.google.com/recaptcha/api/siteverify`,
      null,
      {
        params: {
          secret: process.env.RECAPTCHA_SECRET_KEY,
          response: token,
        },
      }
    );
    return response.data.success;
  } catch (error) {
    console.error("reCAPTCHA verification failed", error);
    return false;
  }
}

// Function to validate password strength
function passwordValidation(password) {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  if (
    password.length >= minLength &&
    hasUpperCase &&
    hasLowerCase &&
    hasDigit &&
    hasSpecialChar
  ) {
    return true;
  } else {
    return false;
  }
}

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];
  //split "Bearer <decode>"-->To take only decode
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    console.log(err);

    if (err) return res.sendStatus(403);

    req.identify = decoded;

    next();
  });
}

async function run() {
  try {
    await client.connect();
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
  }
}

run().catch(console.dir);
