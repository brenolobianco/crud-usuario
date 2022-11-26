import express, { request } from "express";
import users from "./database";
import { v4 as uuidv4 } from "uuid";
import { hash, compare } from "bcryptjs";
import jwt from "jsonwebtoken";
import "dotenv/config";

const app = express();
app.use(express.json());

const ensureAdmMiddleware = (request, response, next) => {
  const user = users.find((el) => el.uuid === request.user.id);

  if (user.isAdm === false) {
    return response.status(403).json({
      message: "You don`t have authorization",
    });
  }

  return next();
};

const ensureAuthMiddleware = (request, response, next) => {
  let authorization = request.headers.authorization;
  if (!authorization) {
    return response.status(401).json({
      message: "Missing authorization headers",
    });
  }
  authorization = authorization.split(" ")[1];

  return jwt.verify(authorization, process.env.SECRET_KEY, (error, decoded) => {
    if (error) {
      return response.status(401).json({
        message: "Invalid token",
      });
    }
    request.user = {
      id: decoded.sub,
    };

    return next();
  });
};

const ensureUserExistsMiddleware = (request, response, next) => {
  const userIndex = users.findIndex((el) => el.uuid === request.params.id);

  if (userIndex === -1) {
    return response.status(404).json({
      message: "User not found!",
    });
  }
  request.user = {
    userIndex: userIndex,
  };

  return next();
};

// SERVICES

const createUsersService = async (userData) => {
  const foundUser = users.find((p) => p.name === userData.name);

  if (foundUser) {
    return [
      409,
      {
        message: "User already exists.",
      },
    ];
  }
  const newUser = {
    ...userData,
    password: await hash(userData.password, 6),
    uuid: uuidv4(),
    isAdm: false,
    createdOn: new Date(),
    updatedOn: new Date(),
  };
  const UserResponse = {
    ...newUser,
  };
  users.push(newUser);
  delete UserResponse.password;
  return [201, UserResponse];
};
const listUsersService = (module) => {
  if (module) {
    const filterUsers = users.filter((item) => item.module === module);
    return [200, filterUsers];
  }
  return [200, users];
};
const retrieveUserService = (id) => {
  const user = users.find((element) => element.uuid === id);

  if (!user) {
    return [
      404,
      {
        message: "User not found!",
      },
    ];
  }
  return [200, user[id]];
};
const changeUserService = (id, changes) => {
  const found = users.find((user) => user.id === id);
  if (found) {
    Object.assign(200).json(found, changes);
  }
  return [200, {}];
};

const deleteUserService = (index) => {
  users.splice(index, 1);
  return [204, {}];
};

const createSessionService = async ({ email, password }) => {
  const user = users.find((el) => {
    return el.email === email;
  });
  if (!user) {
    return [
      401,
      {
        message: "Wrong email or password",
      },
    ];
  }
  const passwordMatch = await compare(password, user.password);
  if (!passwordMatch) {
    return [
      401,
      {
        message: "Wrong email or password",
      },
    ];
  }
  const token = jwt.sign({}, process.env.SECRET_KEY, {
    expiresIn: "24h",
    subject: user.uuid,
  });

  return [
    200,
    {
      token,
    },
  ];
};

//CONTROLLERS

const createUserController = async (request, response) => {
  const [status, user] = await createUsersService(request.body);

  return response.status(status).json(user);
};

const listUsersController = (request, response) => {
  const usersData = listUsersService(request.query.module);
  return response.json(usersData);
};

const retrieveUserController = (request, response) => {
  const id = request.params.uuid;
  const [status, data] = retrieveUserService(id);
  return response.status(status).json(data);
};
const changeUserController = (request, response) => {
  const id = request.params.uuid;
  const changes = request.body;
  const [status, data] = changeUserService(id, changes);
  return response.status(status).json(data);
};
const deleteUserController = (request, response) => {
  const id = request.params.uuid;
  const [status, data] = deleteUserService(id);
  return response.status(status).json(data);
};
const createSessionController = async (request, response) => {
  const [status, data] = await createSessionService(request.body);
  return response.status(status).json(data);
};

// ROTAS

app.post("/users", createUserController);
app.get(
  "/users",
  ensureAuthMiddleware,
  ensureAdmMiddleware,
  listUsersController
);
app.get(
  "/users/profile",
  ensureAuthMiddleware,
  ensureUserExistsMiddleware,
  retrieveUserController
);
app.patch(
  "/users/:id",
  ensureUserExistsMiddleware,
  ensureAuthMiddleware,
  ensureAdmMiddleware,
  changeUserController
);
app.delete(
  "/users/:id",
  ensureAuthMiddleware,
  ensureAdmMiddleware,
  ensureUserExistsMiddleware,
  deleteUserController
);
app.post("/login", createSessionController);

app.listen(3000, () => {
  console.log("Server running in port 3000");
});

export default app;
