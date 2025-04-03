--liquibase formatted sql
--changeset senioravanti:1.2
--comment инициализирую таблицы users, authorities и user_authority
-- Таблица users
INSERT INTO users
  (user_username, user_password)
-- пароль p&6B
VALUES
  ('912fa990-b852-40e9-8d0b-d96289012389', '$2a$10$hydzoD578WtD/JLjxrUzpuHHHG2/4LepOdnG/I64NKCBwA.YbWGaG'
),
-- пароль d63k!UO
(
  '299a6a3c-2f99-41e4-8923-08475c62c711', '$2a$10$54b2o/dZ1dPjFTd/E5BIr.cOHwA0yjaZaM99vEVU/h9Ov1DdfJOK.'
),
-- Пароль #ju0Z
(
  'b6f1178f-fdb1-434f-afbc-f5972714abbb', '$2a$10$fa.ZCHgQvl07mw7RWte8OeWZ.2Hqh79y/ArXxpyBcGN3X7Zvu/Jt.'
);

-- Таблица authorities
INSERT INTO authorities (
  authority_name
)
VALUES (
  'ROLE_ADMIN'
), (
  'ROLE_USER'
);

-- Таблица user_authorities
INSERT INTO user_authorities
  ( user_id, authority_id )
VALUES (
	(
		SELECT user_id
		FROM users
		WHERE user_username = '912fa990-b852-40e9-8d0b-d96289012389'
  ),
  (
		SELECT authority_id
		FROM authorities
		WHERE authority_name = 'ROLE_ADMIN'
  )
),
(
  (
    SELECT user_id
    FROM users
    WHERE user_username = '299a6a3c-2f99-41e4-8923-08475c62c711'
  ),
  (
    SELECT authority_id
    FROM authorities
    WHERE authority_name = 'ROLE_USER'
  )
),
(
  (
    SELECT user_id
    FROM users
    WHERE user_username = 'b6f1178f-fdb1-434f-afbc-f5972714abbb'
  ),
  (
    SELECT authority_id
    FROM authorities
    WHERE authority_name = 'ROLE_ADMIN'
  )
);