import { body } from "express-validator";

const userValidationUser = () => {
  return [
    body("email")
      .trim() // trim the pre and pro space
      .notEmpty() // check whether the email is empty
      .withMessage("Email is required") // sends message
      .isEmail() // checks the format of the email , it should be the format of the email
      .withMessage("Email is invalid"),

    body("username")
      .trim()
      .notEmpty()
      .withMessage("Username is required")
      .isLowercase()
      .withMessage("username should be in the lower case")
      .isLength({ min: 3 })
      .withMessage("username should be at least 3 character long"),

    body("password").trim().notEmpty().withMessage("Password is required"),

    body("Fullname").optional().trim(),
  ];
};

const userLoginValidators = () => {
  return [
    body("email")
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Email is invalid"),
    body("password")
      .trim()
      .notEmpty()
      .withMessage("Password is required")
      .isLowercase(),
  ];
};
export { userValidationUser, userLoginValidators };
