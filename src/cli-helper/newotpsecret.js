import * as OTPAuth from "otpauth";

let secret = new OTPAuth.Secret();

console.log(secret.base32);
