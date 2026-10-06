uv version --bump patch
uv version --bump patch --project packages/provablyfine-client
uv lock
VERSION=$(uv version --short)
uv run towncrier build --version "$VERSION" --yes
cp CHANGELOG.md docs/changelog.md
git add pyproject.toml packages/provablyfine-client/pyproject.toml uv.lock \
        CHANGELOG.md docs/changelog.md changelog.d/
git commit -m "release: $VERSION"
git tag "v$VERSION"
git push && git push --tags
