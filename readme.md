![Conventional Commits](https://img.shields.io/badge/Conventional_Commits-FE5196?style=flat&logo=conventionalcommits&logoColor=white)

# agnostic-template

A language-agnostic template repo

### Setup

Run `./scripts/setup.sh` once after cloning


### Commit messages

Commits must use a conventional prefix, `.githooks/` rejects anything else.

Allowed types: `feat`, `fix`, `hotfix`, `refactor`, `style`, `chore`, `cleanup`, `perf`, `test`, `docs`, `content`

`changelog.md` tracks these changes, generate commits with [git-cliff](https://git-cliff.org):

```sh
git cliff -o changelog.md
```

Commit types map to sections: `feat` to _Added_, `refactor` / `cleanup` / `style` to _Changed_, `fix` / `hotfix` to _Fixed_, `perf` to _Performance_, `docs` / `content` to _Documentation_, `test` to _Tests_. `chore` commits are left out.
