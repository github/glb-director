## Contributing

[fork]: https://github.com/github/glb-director/fork
[pr]: https://github.com/github/glb-director/compare
[code-of-conduct]: CODE_OF_CONDUCT.md

Hi there! We're thrilled that you'd like to contribute to this project. Your help is essential for keeping it great.

Contributions to this project are [released](https://help.github.com/articles/github-terms-of-service/#6-contributions-under-repository-license) to the public under the [project's open source license](LICENSE.md).

Please note that this project is released with a [Contributor Code of Conduct][code-of-conduct]. By participating in this project you agree to abide by its terms.

## Submitting a pull request

0. [Fork][fork] and clone the repository
0. Make sure the tests pass on your machine: `script/cibuild`
0. Create a new branch: `git checkout -b my-branch-name`
0. Make your change, add tests, and make sure the tests still pass
0. Push to your fork and [submit a pull request][pr]
0. Pat your self on the back and wait for your pull request to be reviewed and merged.

Here are a few things you can do that will increase the likelihood of your pull request being accepted:

- Write tests.
- Keep your change as focused as possible. If there are multiple changes you would like to make that are not dependent upon each other, consider submitting them as separate pull requests.
- Write a [good commit message](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html).

## Resources

- [How to Contribute to Open Source](https://opensource.guide/how-to-contribute/)
- [Using Pull Requests](https://help.github.com/articles/about-pull-requests/)
- [GitHub Help](https://help.github.com)

## Releasing

Currently each component in this repo is versioned and released separately as needed. The build and test process is automated requiring Docker (for building) and Vagrant (for multi-machine testing):
```
script/cibuild
```

Once this completes successfully, the `tmp/build` directory will contain a `.deb` file for each component and they can be released to the apt source by an authorised maintainer:
```
package_cloud push github/glb-director/debian/jessie glb-<component>_<version>.deb
package_cloud push github/glb-director/debian/stretch glb-<component>_<version>.deb
```
