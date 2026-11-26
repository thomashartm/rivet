-- The playground schema. Runs once, when the data volume is empty.
CREATE SCHEMA playground;
ALTER DATABASE playground SET search_path = playground, public;
SET search_path = playground, public;

CREATE TABLE customers (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name       text        NOT NULL,
    email      text        NOT NULL UNIQUE,
    country    text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE products (
    id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name     text          NOT NULL,
    price    numeric(10,2) NOT NULL CHECK (price >= 0),
    in_stock boolean       NOT NULL DEFAULT true
);

CREATE TABLE orders (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    customer_id bigint      NOT NULL REFERENCES customers (id),
    ordered_at  timestamptz NOT NULL DEFAULT now(),
    status      text        NOT NULL CHECK (status IN ('open', 'paid', 'shipped', 'cancelled'))
);

CREATE TABLE order_items (
    order_id   bigint  NOT NULL REFERENCES orders (id),
    product_id bigint  NOT NULL REFERENCES products (id),
    quantity   integer NOT NULL CHECK (quantity > 0),
    PRIMARY KEY (order_id, product_id)
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
