# License

Open Sesame is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

## Quick Summary

**You are free to:**

- Use Open Sesame for any purpose (personal, commercial, etc.)
- Study and modify the source code
- Distribute copies of Open Sesame
- Distribute modified versions

**Under these conditions:**

- You must disclose the source code when distributing
- Modified versions must also be licensed under GPL-3.0
- You must include the original copyright and license notices
- You must state significant changes made to the software

## Full License Text

```text
Open Sesame - Vimium-style window switcher for COSMIC desktop
Copyright (C) 2024 usrbinkat

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
```

## Full License Document

The complete GPL-3.0 license text is available in the repository:

- **File:** [`LICENSE`](https://github.com/ScopeCreep-zip/open-sesame/blob/main/LICENSE)
- **Online:** [https://www.gnu.org/licenses/gpl-3.0.en.html](https://www.gnu.org/licenses/gpl-3.0.en.html)

## Why GPL-3.0?

Open Sesame is licensed under GPL-3.0 to ensure:

1. **Freedom** - Users can always access and modify the source code
2. **Transparency** - No proprietary forks that hide improvements
3. **Community** - Improvements benefit everyone
4. **Copyleft** - Derived works must remain free software

## Dependencies

Open Sesame uses several open-source libraries, each with their own licenses:

### Runtime Dependencies

| Library | License | Purpose |
|---------|---------|---------|
| [tiny-skia](https://github.com/RazrFalcon/tiny-skia) | BSD-3-Clause | 2D graphics rendering |
| [fontdue](https://github.com/mooman219/fontdue) | MIT OR Apache-2.0 | Font rasterization |
| [wayland-client](https://github.com/Smithay/wayland-rs) | MIT | Wayland protocol client |
| [smithay-client-toolkit](https://github.com/Smithay/client-toolkit) | MIT | Wayland toolkit |
| [toml](https://github.com/toml-rs/toml) | MIT OR Apache-2.0 | TOML parsing |
| [serde](https://github.com/serde-rs/serde) | MIT OR Apache-2.0 | Serialization |
| [anyhow](https://github.com/dtolnay/anyhow) | MIT OR Apache-2.0 | Error handling |
| [tracing](https://github.com/tokio-rs/tracing) | MIT | Logging |

### Build Dependencies

| Library | License | Purpose |
|---------|---------|---------|
| [clap](https://github.com/clap-rs/clap) | MIT OR Apache-2.0 | CLI parsing |
| [cargo-deb](https://github.com/kornelski/cargo-deb) | MIT | Debian packaging |

**License Compatibility:**
All dependencies use permissive licenses (MIT, Apache-2.0, BSD) that are compatible with GPL-3.0.

## Contributing

By contributing to Open Sesame, you agree that your contributions will be licensed under the GPL-3.0 license.

See the [Contributing Guide](../developer-guide/contributing.md) for details.

## Commercial Use

**Yes, you can use Open Sesame commercially.**

The GPL-3.0 license permits commercial use without restriction. You can:

- Use Open Sesame in a commercial environment
- Bundle Open Sesame with commercial software
- Modify Open Sesame for commercial purposes

**However:**

- If you distribute Open Sesame (or a modified version), you must provide the source code
- Recipients have the same rights you do (GPL-3.0 applies)
- You cannot add additional restrictions

## Trademark

"Open Sesame" is not a registered trademark. You are free to use the name when referring to this software.

**However:**

- Do not imply official endorsement without permission
- Modified versions should be clearly identified as such
- Consider using a different name for substantial forks

## Contact

For licensing questions or special licensing arrangements, please contact:

- **GitHub Issues:** [https://github.com/ScopeCreep-zip/open-sesame/issues](https://github.com/ScopeCreep-zip/open-sesame/issues)
- **Email:** (See GitHub profile)

## Disclaimer

```text
THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

## Additional Resources

- [GNU GPL-3.0 FAQ](https://www.gnu.org/licenses/gpl-faq.html)
- [GPL-3.0 License Explained](https://www.gnu.org/licenses/quick-guide-gplv3.html)
- [Choose a License Guide](https://choosealicense.com/licenses/gpl-3.0/)
- [SPDX License Identifier](https://spdx.org/licenses/GPL-3.0-only.html)

## See Also

- [Changelog](./changelog.md) - Version history and release notes
- [Contributing Guide](../developer-guide/contributing.md) - How to contribute
