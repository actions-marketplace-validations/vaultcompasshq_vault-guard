// False positive candidates: local / dev / docker / placeholder connection
// strings. These are config, not leaked credentials -- the dominant real-world
// FP source (docker-compose, .env.example, test setup).
const LOCAL_PG = "postgres://prisma:prisma@localhost:5432/tests";
const DEFAULT_MYSQL = "mysql://root:root@localhost:3306/tests";
const DOCKER_MYSQL = "mysql://root:root@mysql/tests";
const USERPASS = "postgres://user:pass@localhost:5432/db";
const TEMPLATE = "mysql://USER:PASSWORD@aws.connect.psdb.cloud/DATABASE";
const ENV_INTERP = "postgres://app:${DB_PASSWORD}@db.prod.example-corp.com/main";
