const { nanoid } = require('nanoid');

class User {
  constructor({ email, first_name, last_name, passwordHash, age }) {
    this.id = nanoid(6);
    this.email = email;
    this.first_name = first_name;
    this.last_name = last_name;
    this.passwordHash = passwordHash;
    this.age = age;
    this.created_at = new Date().toISOString();
  }

  toJSON() {
    const { passwordHash, ...safeUser } = this;
    return safeUser;
  }
}

module.exports = User;