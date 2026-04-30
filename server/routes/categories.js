const express = require('express');
const router = express.Router();
const { body, param, validationResult } = require('express-validator');
const auth = require('../middleware/auth');
const Category = require('../models/Category');

const handleValidation = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
  }
  next();
};

// GET /api/categories - Get all categories for the user
router.get('/', auth, async (req, res) => {
  try {
    const categories = await Category.find({ userId: req.user.id }).sort({ name: 1 });
    res.json(categories);
  } catch (err) {
    console.error("Error in GET /api/categories:", err);
    res.status(500).json({ message: "Server Error", error: err.message });
  }
});

// POST /api/categories - Create a new category
router.post(
  '/',
  auth,
  [
    body('name').isString().trim().isLength({ min: 1, max: 100 }),
    body('icon').optional().isString().isLength({ min: 0, max: 10 }),
    body('color').optional().isString().isLength({ min: 0, max: 20 })
  ],
  handleValidation,
  async (req, res) => {
  try {
    const { name, icon, color } = req.body;

    if (!name || name.trim().length === 0) {
      return res.status(400).json({ message: "Category name is required" });
    }

    // Check if category already exists for this user
    const existingCategory = await Category.findOne({ 
      userId: req.user.id, 
      name: name.trim() 
    });

    if (existingCategory) {
      return res.status(400).json({ message: "Category already exists" });
    }

    const newCategory = new Category({
      userId: req.user.id,
      name: name.trim(),
      icon: icon || '📁',
      color: color || '#8B5CF6'
    });

    const savedCategory = await newCategory.save();
    res.status(201).json(savedCategory);
  } catch (err) {
    console.error("Error in POST /api/categories:", err);
    res.status(500).json({ message: "Server Error", error: err.message });
  }
});

// PUT /api/categories/:id - Update a category
router.put(
  '/:id',
  auth,
  [
    param('id').isString().isLength({ min: 1 }),
    body('name').isString().trim().isLength({ min: 1, max: 100 }),
    body('icon').optional().isString().isLength({ min: 0, max: 10 }),
    body('color').optional().isString().isLength({ min: 0, max: 20 })
  ],
  handleValidation,
  async (req, res) => {
  try {
    const { name, icon, color } = req.body;

    if (!name || name.trim().length === 0) {
      return res.status(400).json({ message: "Category name is required" });
    }

    // Check if another category with the same name exists for this user
    const existingCategory = await Category.findOne({ 
      userId: req.user.id, 
      name: name.trim(),
      _id: { $ne: req.params.id }
    });

    if (existingCategory) {
      return res.status(400).json({ message: "Category name already exists" });
    }

    const updatedCategory = await Category.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.id },
      { 
        name: name.trim(),
        icon: icon || '📁',
        color: color || '#8B5CF6'
      },
      { new: true }
    );

    if (!updatedCategory) {
      return res.status(404).json({ message: "Category not found" });
    }

    res.json(updatedCategory);
  } catch (err) {
    console.error("Error in PUT /api/categories:", err);
    res.status(500).json({ message: "Server Error", error: err.message });
  }
});

// DELETE /api/categories/:id - Delete a category
router.delete(
  '/:id',
  auth,
  [param('id').isString().isLength({ min: 1 })],
  handleValidation,
  async (req, res) => {
  try {
    const deletedCategory = await Category.findOneAndDelete({ 
      _id: req.params.id, 
      userId: req.user.id 
    });

    if (!deletedCategory) {
      return res.status(404).json({ message: "Category not found" });
    }

    res.json({ message: "Category deleted successfully" });
  } catch (err) {
    console.error("Error in DELETE /api/categories:", err);
    res.status(500).json({ message: "Server Error", error: err.message });
  }
});

module.exports = router;
