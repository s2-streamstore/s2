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
    GLIBC_VERSION=$(ldd --version 2>/dev/null | head -n1 | grep -oE '[0-9]+\\.[0-9]+$' || echo "0.0")
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
elif echo "${OS}" | grep -qE '^(MINGW|MSYS|CYGWIN)'
then
    echo_red "Platform not supported by install.sh."
    echo_em "${OS} on ${ARCH}"
    echo_white "Windows users: download a Windows zip from the GitHub releases
or install via Cargo (cargo install --locked s2-cli)."
    exit 1
fi

if [ -z "${TARGET}" ]
then
    echo_red "Platform not supported."
    echo_em "${OS} on ${ARCH}"
    echo_white "It looks like this platform is not supported. We're sorry about that.
Visit https://github.com/s2-streamstore/s2 to file an issue, and build
from source."
    exit 1
fi

REPO="${S2_REPO:-s2-streamstore/s2}"
DOWNLOAD_URI="latest/download"
S2_VERSION="latest"
if [ -n "${VERSION}" ]
then
    case "${VERSION}" in
        s2-cli-v*) TAG="${VERSION}" ;;
        v*) TAG="s2-cli-${VERSION}" ;;
        *) TAG="s2-cli-v${VERSION}" ;;
    esac
    S2_VERSION="${TAG}"
    DOWNLOAD_URI="download/${TAG}"
fi

BIN_PATH="${HOME}/.s2/bin"
test -d "${BIN_PATH}" || mkdir -p "${BIN_PATH}"

DOWNLOAD_PATH=`mktemp`
PWD=`pwd`
URL="https://github.com/${REPO}/releases/${DOWNLOAD_URI}/${TARGET}"

echo_blue "Installing S2 CLI"
echo_em "S2 Version: ${S2_VERSION}"

curl --progress-bar -fSL "${URL}" -o "${DOWNLOAD_PATH}" \
    && unzip -o -d "${BIN_PATH}" "${DOWNLOAD_PATH}" >/dev/null \
    && chmod a+x "${BIN_PATH}/s2" \
    || exit 1

rm -f "${DOWNLOAD_PATH}"

echo_blue "Successfully downloaded"

EXISTING_S2_PATH=$(command -v s2 2>/dev/null || true)
NEEDS_PATH_UPDATE=
if [ -n "${EXISTING_S2_PATH}" ] && [ "${EXISTING_S2_PATH}" != "${BIN_PATH}/s2" ]
then
    NEEDS_PATH_UPDATE=1
    echo_yellow "WARNING: Found existing s2 at ${EXISTING_S2_PATH}"
    echo_em "New binary is at ${BIN_PATH}/s2"
fi

# Add the bin to $PATH if it doesn't exist or isn't taking precedence.
# Thanks to Pulumi install script for the inspiration.
if [ -z "${EXISTING_S2_PATH}" ] || [ -n "${NEEDS_PATH_UPDATE}" ]; then
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
        LINE_TO_ADD="export PATH=${BIN_PATH}:\\$PATH"
        if ! grep -q "${BIN_PATH}" "${PROFILE_FILE}"; then
            echo_white "Adding ${BIN_PATH} to \\$PATH in ${PROFILE_FILE}"
            printf "\\n# add S2 to the PATH\\n%s\\n" "${LINE_TO_ADD}" >> "${PROFILE_FILE}"
        else
            echo_yellow "WARNING: ${BIN_PATH} is already in your PATH."
            [ -n "${EXISTING_S2_PATH}" ] && echo_em "Ensure ${BIN_PATH} appears before ${EXISTING_S2_PATH}"
        fi

        echo_yellow "WARNING: Please restart your shell or add ${BIN_PATH} to your \\$PATH"
    else
        echo_yellow "WARNING: Please add ${BIN_PATH} to your \\$PATH"
    fi
fi

echo_green "S2 CLI installed as"
echo_em "${BIN_PATH}/s2"
echo_green "Get started with S2:"
echo_em "https://s2.dev/docs/quickstart"
