"""Curated popular package names for typosquatting detection."""

# Top npm packages (unscoped base names + common scoped patterns)
POPULAR_NPM: set[str] = {
    "react", "react-dom", "next", "express", "lodash", "axios", "webpack",
    "typescript", "eslint", "prettier", "vite", "tailwindcss", "mongoose",
    "moment", "uuid", "chalk", "commander", "dotenv", "cors", "helmet",
    "jsonwebtoken", "bcrypt", "passport", "socket.io", "redis", "pg",
    "mysql", "sequelize", "prisma", "@prisma/client", "firebase", "aws-sdk",
    "@aws-sdk/client-s3", "stripe", "nodemailer", "multer", "joi", "zod",
    "rxjs", "vue", "angular", "svelte", "jest", "mocha", "chai", "sinon",
    "babel-core", "@babel/core", "rollup", "parcel", "gulp", "grunt",
    "request", "node-fetch", "got", "debug", "semver", "minimist",
    "colors", "faker", "date-fns", "dayjs", "classnames", "styled-components",
    "@types/node", "@types/react", "@types/express", "ts-node", "nodemon",
    "concurrently", "cross-env", "rimraf", "glob", "fs-extra", "yaml",
    "marked", "highlight.js", "chart.js", "d3", "three", "pixi.js",
    "electron", "puppeteer", "playwright", "cypress", "storybook",
    "create-react-app", "gatsby", "nuxt", "remix", "turbo", "lerna",
    "husky", "lint-staged", "commitlint", "semantic-release",
}

# Top PyPI packages
POPULAR_PYPI: set[str] = {
    "requests", "urllib3", "certifi", "charset-normalizer", "idna",
    "pip", "setuptools", "wheel", "numpy", "pandas", "scipy", "matplotlib",
    "django", "flask", "fastapi", "uvicorn", "gunicorn", "celery", "redis",
    "sqlalchemy", "psycopg2", "psycopg2-binary", "pymongo", "boto3",
    "botocore", "cryptography", "pyjwt", "passlib", "bcrypt", "paramiko",
    "pillow", "opencv-python", "scikit-learn", "tensorflow", "torch",
    "transformers", "openai", "anthropic", "langchain", "pydantic",
    "httpx", "aiohttp", "beautifulsoup4", "lxml", "pyyaml", "toml",
    "click", "typer", "rich", "colorama", "tqdm", "pytest", "unittest2",
    "black", "flake8", "mypy", "isort", "ruff", "poetry", "virtualenv",
    "jinja2", "werkzeug", "itsdangerous", "markupsafe", "six", "attrs",
    "python-dateutil", "pytz", "arrow", "pendulum", "orjson", "ujson",
    "stripe", "sendgrid", "twilio", "boto", "google-cloud-storage",
    "azure-storage-blob", "kubernetes", "docker", "ansible", "fabric",
}

# Known malicious / compromised package names (public advisories)
KNOWN_MALICIOUS: dict[str, str] = {
    # Historical npm malware campaigns (representative samples)
    "eslint-scope": "Compromised eslint-scope publish (2018 supply-chain attack)",
    "event-stream": "Malicious flatmap-stream dependency (2018)",
    "ua-parser-js": "Compromised versions with crypto miner (2021)",
    "coa": "Compromised with password stealer (2021)",
    "rc": "Compromised with password stealer (2021)",
    "colors": "Author sabotaged package (2022)",
    "faker": "Renamed/migrated — verify source is @faker-js/faker",
    "node-ipc": "Protestware targeting Russian/Belarusian IPs (2022)",
    "peacenotwar": "Protestware npm package",
    # Typosquat campaigns
    "crossenv": "Typosquat of cross-env",
    "jquerry": "Typosquat of jquery",
    "python3-dateutil": "Typosquat of python-dateutil",
    "requets": "Typosquat of requests",
    "urlib3": "Typosquat of urllib3",
    "python-sqlite": "Typosquat targeting sqlite3 stdlib confusion",
}

SIGSTORE_MARKERS = (
    "cosign",
    "sigstore",
    "slsa-verifier",
    "slsa-github-generator",
    "gitsign",
    "rekor",
)

CONTAINER_PUBLISH_MARKERS = (
    "docker push",
    "build-push-action",
    "ghcr.io",
    "ecr.",
    "gcr.io",
    "azurecr.io",
    "docker/build-push-action",
    "kaniko",
    "skopeo copy",
)

RISKY_LIFECYCLE_SCRIPTS = frozenset({
    "preinstall",
    "postinstall",
    "prepare",
    "preuninstall",
    "install",
})
