# PlumeImpactor

[![GitHub Release](https://img.shields.io/github/v/release/khcrysalis/PlumeImpactor?include_prereleases)](https://github.com/khcrysalis/PlumeImpactor/releases)
[![GitHub License](https://img.shields.io/github/license/khcrysalis/PlumeImpactor?color=%23C96FAD)](https://github.com/khcrysalis/PlumeImpactor/blob/main/LICENSE)
[![Sponsor Me](https://img.shields.io/static/v1?label=Sponsor&message=%E2%9D%A4&logo=GitHub&color=%23fe8e86)](https://github.com/sponsors/khcrysalis)

WIP open-source, cross-platform, and feature rich iOS/tvOS sideloading application. Supporting macOS, Linux, and (hopefully) Windows.

### Features
- User friendly and clean UI.
- Sign and install applications.

## Structure

The project is seperated in multiple modules, all serve single or multiple uses depending on their importance.

| Module               | Description                                                                                                                   |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `apps/plumeimpactor` | GUI interface for the crates shown below, backend using wxWidgets (with a rust ffi wrapper, wxDragon)                         |
| `apps/plumesign`     | Simple CLI interface for signing, using `clap`.                                                                       |
| `crates/grand_slam`  | Handles all api request used for communicating with Apple developer services, along with providing auth for Apple's grandslam |

## Acknowledgements

- [SAMSAM](https://github.com/khcrysalis) – The maker.
- [SideStore](https://github.com/SideStore/apple-private-apis) – Grandslam auth & Omnisette.
- [Sideloader](https://github.com/Dadoum/Sideloader) – Apple Developer API references.
- [idevice](https://github.com/jkcoxson/idevice) – Used for communication with `installd`, specifically for sideloading the apps to your devices.

## License

Project is licensed under the MIT license. You can see the full details of the license [here](https://github.com/khcrysalis/PlumeImpactor/blob/main/LICENSE).
