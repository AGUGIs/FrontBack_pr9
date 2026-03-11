const { nanoid } = require('nanoid');

class Product {
  constructor({ title, category, description, price }) {
    this.id = nanoid(6);
    this.title = title;
    this.category = category;
    this.description = description;
    this.price = Number(price);
    this.created_at = new Date().toISOString();
    this.updated_at = new Date().toISOString();
  }

  update(data) {
    Object.assign(this, data, { updated_at: new Date().toISOString() });
    return this;
  }
}

module.exports = Product;