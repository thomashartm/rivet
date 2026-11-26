-- The playground database for MySQL: the same tables as the PostgreSQL
-- playground. Runs once, when the data volume is empty.
USE playground;

CREATE TABLE customers (
    id         bigint       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name       varchar(200) NOT NULL,
    email      varchar(200) NOT NULL UNIQUE,
    country    char(2)      NOT NULL,
    created_at timestamp    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
    id       bigint        NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name     varchar(200)  NOT NULL,
    price    decimal(10,2) NOT NULL CHECK (price >= 0),
    in_stock boolean       NOT NULL DEFAULT true
);

CREATE TABLE orders (
    id          bigint      NOT NULL AUTO_INCREMENT PRIMARY KEY,
    customer_id bigint      NOT NULL,
    ordered_at  timestamp   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status      varchar(20) NOT NULL CHECK (status IN ('open', 'paid', 'shipped', 'cancelled')),
    FOREIGN KEY (customer_id) REFERENCES customers (id)
);

CREATE TABLE order_items (
    order_id   bigint NOT NULL,
    product_id bigint NOT NULL,
    quantity   int    NOT NULL CHECK (quantity > 0),
    PRIMARY KEY (order_id, product_id),
    FOREIGN KEY (order_id) REFERENCES orders (id),
    FOREIGN KEY (product_id) REFERENCES products (id)
);

INSERT INTO customers (name, email, country) VALUES
    ('Ada Lovelace',      'ada@example.com',      'GB'),
    ('Grace Hopper',      'grace@example.com',    'US'),
    ('Alan Turing',       'alan@example.com',     'GB'),
    ('Margaret Hamilton', 'margaret@example.com', 'US'),
    ('Konrad Zuse',       'konrad@example.com',   'DE');

INSERT INTO products (name, price, in_stock) VALUES
    ('Keyboard', 49.90, true),
    ('Mouse',    19.50, true),
    ('Monitor', 229.00, true),
    ('Cable',     4.99, false);

INSERT INTO orders (customer_id, status) VALUES
    (1, 'paid'), (2, 'shipped'), (2, 'open'), (3, 'cancelled'), (5, 'paid');

INSERT INTO order_items (order_id, product_id, quantity) VALUES
    (1, 1, 1), (1, 2, 2), (2, 3, 1), (3, 4, 5), (4, 2, 1), (5, 1, 1), (5, 3, 2);
