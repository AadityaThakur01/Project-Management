import { validationResult } from "express-validator";
import { ApiError } from "../utils/api-error.js";

export const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (errors.isEmpty()) {
    // if the error is empty then move to next
    return next();
  }
  const extractedErrors = [];
  errors.array().map(
    (
      err, // extracted errors loops through them and giving error path and error message
    ) =>
      extractedErrors.push({
        [err.path]: err.msg,
      }),
  );
  throw new ApiError(422, "Received data is not validate", extractedErrors);
};
