--liquibase formatted sql
--changeset senioravanti:1.2
--comment инициализирую таблицы users, authorities и user_authority
-- Таблица users
INSERT INTO users
  (user_id, user_username, user_password)
-- пароль p&6B
VALUES
  (uuid('466c8d94-28d7-402b-ac32-9e40748e908e'), 'jeff-wisoky',
   '$2a$10$hydzoD578WtD/JLjxrUzpuHHHG2/4LepOdnG/I64NKCBwA.YbWGaG'
),
-- пароль d63k!UO
(
  uuid('c2032f4f-4db2-4c42-b606-61b8594c1681'),
   'morgan-kolovratov', '$2a$10$54b2o/dZ1dPjFTd/E5BIr.cOHwA0yjaZaM99vEVU/h9Ov1DdfJOK.'
),
-- Пароль #ju0Z
(
  uuid('555ac44e-67ec-4f5d-a873-c1cee32bcb81'), 'antonio-harley-danger', '$2a$10$fa.ZCHgQvl07mw7RWte8OeWZ.2Hqh79y/ArXxpyBcGN3X7Zvu/Jt.'
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
	uuid('466c8d94-28d7-402b-ac32-9e40748e908e'),
  (
		SELECT authority_id
		FROM authorities
		WHERE authority_name = 'ROLE_ADMIN'
  )
),
(
  uuid('c2032f4f-4db2-4c42-b606-61b8594c1681'),
  (
    SELECT authority_id
    FROM authorities
    WHERE authority_name = 'ROLE_USER'
  )
),
(
  uuid('555ac44e-67ec-4f5d-a873-c1cee32bcb81'),
  (
    SELECT authority_id
    FROM authorities
    WHERE authority_name = 'ROLE_ADMIN'
  )
);