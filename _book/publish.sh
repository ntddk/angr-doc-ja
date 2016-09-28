cp -r _book/.git ./.git_tmp
gitbook build
cp -r ./.git_tmp _book/.git
cd _book/
git checkout gh-pages
git add --all .
git commit -m 'update'
git remote set-url origin git@github.com:ntddk/angr-doc-ja.git
git push origin -u gh-pages