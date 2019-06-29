const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const favoriteSchema = new Schema({

});

var Favorites = mongoose.model('Favorite', favoriteSchema);

module.exports = Dishes;