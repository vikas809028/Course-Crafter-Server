import express from "express";
import passport from "passport";
import jwt from "jsonwebtoken";

const router = express.Router();

// Google Authentication Route
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));

// Google Callback Route
router.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    const token = jwt.sign({ id: req.user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.cookie("token", token, { httpOnly: true, secure: true, sameSite: "None" });

    res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
  }
);

// GitHub Authentication Route
router.get("/github", passport.authenticate("github", { scope: ["user:email"] }));

// GitHub Callback Route
router.get(
  "/github/callback",
  passport.authenticate("github", { failureRedirect: "/login" }),
  (req, res) => {
    const token = jwt.sign({ id: req.user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.cookie("token", token, { httpOnly: true, secure: true, sameSite: "None" });

    res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
  }
);

// Logout Route
router.get("/logout", (req, res) => {
  req.logout(() => {
    res.cookie("token", "", { maxAge: 0 });
    res.redirect(process.env.FRONTEND_URL);
  });
});

export default router;
