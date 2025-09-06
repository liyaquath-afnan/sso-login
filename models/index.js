const { sequelize } = require('../config/database');
const User = require('./User');
const UserProfile = require('./UserProfile');

// Define associations
User.hasOne(UserProfile, {
  foreignKey: 'username',
  sourceKey: 'username',
  as: 'profile'
});

UserProfile.belongsTo(User, {
  foreignKey: 'username',
  targetKey: 'username',
  as: 'user'
});

// Export models and sequelize instance
module.exports = {
  sequelize,
  User,
  UserProfile
};
