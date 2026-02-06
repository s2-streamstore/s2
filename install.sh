#!/bin/sh -e

RESET="\\033[0m"
RED="\\033[31;1m"
GREEN="\\033[32;1m"
YELLOW="\\033[33;1m"
BLUE="\\033[34;1m"
WHITE="\\033[37;1m"

echo_green() {
    [ -z "${SILENT}" ] && printf "%b%s%b\\n" "${GREEN}" "$1" "${RESET}"
    return 0
}

echo_red() {
    printf "%b%s%b\\n" "${RED}" "$1" "${RESET}"
}

echo_yellow() {
    [ -z "${SILENT}" ] && printf "%b%s%b\\n" "${YELLOW}" "$1" "${RESET}"
    return 0
}

echo_blue() {
    [ -z "${SILENT}" ] && printf "%b%s%b\\n" "${BLUE}" "$1" "${RESET}"
    return 0
}

echo_white() {
    [ -z "${SILENT}" ] && printf "%b%s%b\\n" "${WHITE}" "$1" "${RESET}"
    return 0
}

echo_em() {
    [ -z "${SILENT}" ] && echo "    $1"
}

OS=$(uname -s)
ARCH=$(uname -m)

# Check if we need musl (glibc < 2.38 or musl-based system like Alpine)
needs_musl() {
    # Check if it's a musl-based system (e.g., Alpine)
    if ldd --version 2>&1 | grep -q musl; then
        return 0
    fi
    # Check glibc version
    GLIBC_VERSION=$(ldd --version 2>/dev/null | head -n1 | grep -oE '[0-9]+\.[0-9]+$' || echo "0.0")
    GLIBC_MAJOR=$(echo "${GLIBC_VERSION}" | cut -d. -f1)
    GLIBC_MINOR=$(echo "${GLIBC_VERSION}" | cut -d. -f2)
    # Need musl if glibc < 2.38
    if [ "${GLIBC_MAJOR}" -lt 2 ] 2>/dev/null || \
       { [ "${GLIBC_MAJOR}" -eq 2 ] && [ "${GLIBC_MINOR}" -lt 38 ]; } 2>/dev/null; then
        return 0
    fi
    return 1
}

TARGET=

if [ "${OS}" = "Linux" ]
then
    if [ "${ARCH}" = "x86_64" -o "${ARCH}" = "amd64" ]
    then
        if needs_musl; then
            TARGET="s2-x86_64-unknown-linux-musl.zip"
        else
            TARGET="s2-x86_64-unknown-linux-gnu.zip"
        fi
    elif [ "${ARCH}" = "aarch64" -o "${ARCH}" = "arm64" ]
    then
        if needs_musl; then
            TARGET="s2-aarch64-unknown-linux-musl.zip"
        else
            TARGET="s2-aarch64-unknown-linux-gnu.zip"
        fi
    fi
elif [ "${OS}" = "Darwin" ]
then
    if [ "${ARCH}" = "x86_64" -o "${ARCH}" = "amd64" ]
    then
        TARGET="s2-x86_64-apple-darwin.zip"
    elif [ "${ARCH}" = "aarch64" -o "${ARCH}" = "arm64" ]
    then
        TARGET="s2-aarch64-apple-darwin.zip"
    fi
fi

if [ -z "${TARGET}" ]
then
    echo_red "Platform not supported."
    echo_em "${OS} on ${ARCH}"
    echo_white "It looks like this platform is not supported. We're sorry about that.
Visit https://github.com/s2-streamstore/s2-cli to file an issue, and build 
from source."
    exit 1
fi

DOWNLOAD_URI="latest/download"
S2_VERSION="Latest"
if [ -n "${VERSION}" ]
then
    S2_VERSION="v${VERSION}"
    DOWNLOAD_URI="download/${VERSION}"
fi

BIN_PATH="${HOME}/.s2/bin"
test -d "${BIN_PATH}" || mkdir -p "${BIN_PATH}"

DOWNLOAD_PATH=`mktemp`
PWD=`pwd`
URL="https://github.com/s2-streamstore/s2-cli/releases/${DOWNLOAD_URI}/${TARGET}"

echo_blue "⏳ Installing S2 CLI"
echo_em "S2 Version: ${S2_VERSION}"

curl --progress-bar -fSL "${URL}" -o "${DOWNLOAD_PATH}" \
    && unzip -o -d "${BIN_PATH}" "${DOWNLOAD_PATH}" >/dev/null \
    && chmod a+x "${BIN_PATH}/s2" \
    || exit 1

rm -f "${DOWNLOAD_PATH}"

echo_blue "🌐 Successfully Downloaded"

# Add the bin to $PATH if it doesn't exist.
# Thanks to Pulumi install script for the inspiration.
if ! command -v s2 >/dev/null; then
    SHELL_NAME=$(basename "${SHELL}")
    PROFILE_FILE=""

    if [ "${SHELL_NAME}" = "bash" ]
    then
      if [ "${OS}" = "Darwin" ]
      then
        if [ -e "${HOME}/.bash_profile" ]; then
            PROFILE_FILE="${HOME}/.bash_profile"
        elif [ -e "${HOME}/.bashrc" ]; then
            PROFILE_FILE="${HOME}/.bashrc"
        fi
      else
        if [ -e "${HOME}/.bashrc" ]; then
            PROFILE_FILE="${HOME}/.bashrc"
        elif [ -e "${HOME}/.bash_profile" ]; then
            PROFILE_FILE="${HOME}/.bash_profile"
        fi
      fi
    elif [ "${SHELL_NAME}" = "zsh" ]
    then
        if [ -e "${ZDOTDIR:-$HOME}/.zshrc" ]; then
            PROFILE_FILE="${ZDOTDIR:-$HOME}/.zshrc"
        fi
    fi

    if [ -n "${PROFILE_FILE}" ]; then
        LINE_TO_ADD="export PATH=\$PATH:${BIN_PATH}"
        if ! grep -q "# add S2 to the PATH" "${PROFILE_FILE}"; then
            echo_white "➕ Adding ${BIN_PATH} to \$PATH in ${PROFILE_FILE}"
            printf "\\n# add S2 to the PATH\\n%s\\n" "${LINE_TO_ADD}" >> "${PROFILE_FILE}"
        fi

        echo_yellow "⚠️ Please restart your shell or add ${BIN_PATH} to your \$PATH"
    else
        echo_yellow "⚠️ Please add ${BIN_PATH} to your \$PATH"
    fi
fi

echo_green "✅ S2 CLI installed as"
echo_em "${BIN_PATH}/s2"
echo_green "⚡️ Get started with S2:"
echo_em "https://s2.dev/docs/quickstart"
