--liquibase formatted sql
--changeset senioravanti:1.2
--comment Таблицы, хр. инф. о зарегистрированных пользователях и их привилегиях
DROP TABLE IF EXISTS user_authorities;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS authorities;

CREATE TABLE IF NOT EXISTS users (
  user_id UUID PRIMARY KEY,

  user_username varchar(200) NOT NULL UNIQUE,
  user_password varchar(500) NOT NULL CHECK (LENGTH(user_password) >= 6)
);

CREATE TABLE IF NOT EXISTS authorities (
  authority_id smallserial PRIMARY KEY,
  authority_name varchar(200) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS user_authorities (
  user_id UUID REFERENCES users ON DELETE RESTRICT,
  authority_id smallint REFERENCES authorities ON DELETE RESTRICT,
  PRIMARY KEY (user_id, authority_id)
);