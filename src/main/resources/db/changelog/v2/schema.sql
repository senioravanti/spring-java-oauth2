--liquibase formatted sql
--changeset senioravanti:1.1
--comment Таблица, хр. инф. о решении сервера относительно запроса клиента на получение определенных привилегий
DROP TABLE IF EXISTS oauth2_authorization_consent;

CREATE TABLE IF NOT EXISTS oauth2_authorization_consent (
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorities varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);