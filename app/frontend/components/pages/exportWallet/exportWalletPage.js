const {h, Component} = require('preact')
const connect = require('unistore/preact').connect

const actions = require('../../../actions')
const CloseIcon = require('../../common/svg').CloseIcon

class ExportWalletDialog extends Component {
  constructor(props) {
    super(props)
    this.state = {
      walletName: 'Cardano_lite',
      isWalletNameValid: true,
      password: '',
      confirmation: '',
      isPasswordDirty: false,
      isPasswordConfirmationDirty: false,
      showError: false,
      showSuccess: false,
    }

    this.updateWalletName = this.updateWalletName.bind(this)
    this.updatePassword = this.updatePassword.bind(this)
    this.updatePasswordConfirmation = this.updatePasswordConfirmation.bind(this)
    this.exportJsonWallet = this.exportJsonWallet.bind(this)
    this.closeExportJsonWalletDialog = this.closeExportJsonWalletDialog.bind(this)
    this.touchPasswordConfirmationField = this.touchPasswordConfirmationField.bind(this)
    this.touchPasswordField = this.touchPasswordField.bind(this)
  }

  componentDidMount() {
    this.walletNameField.focus()
  }

  closeExportJsonWalletDialog() {
    this.setState({
      walletName: 'cardano_lite_wallet',
      isWalletNameValid: true,
      password: '',
      isPasswordDirty: false,
      isPasswordConfirmationDirty: false,
      confirmation: '',
      isPasswordValid: false,
    })

    this.props.closeExportJsonWalletDialog()
  }

  exportJsonWallet(e) {
    this.props.exportJsonWallet(this.state.password, this.state.walletName)
    this.setState({showSuccess: true, password: '', confirmation: ''})
    this.walletNameField.focus()
    setTimeout(() => this.state.showSuccess && this.setState({showSuccess: false}), 3000)
  }

  isPasswordValid(password, confirmation) {
    if (password !== confirmation || !password.trim().length) {
      return false
    } else {
      return true
    }
  }

  updatePassword(e) {
    this.setState({
      password: e.target.value,
      isPasswordValid: this.isPasswordValid(e.target.value, this.state.confirmation),
    })
  }

  updatePasswordConfirmation(e) {
    this.setState({
      confirmation: e.target.value,
      isPasswordValid: this.isPasswordValid(this.state.password, e.target.value),
    })
  }

  updateWalletName(e) {
    this.setState({
      walletName: e.target.value,
      isWalletNameValid: /^[a-zA-Z0-9-_]+$/.test(e.target.value),
    })
  }

  touchPasswordField() {
    this.setState({isPasswordDirty: true})
  }

  touchPasswordConfirmationField() {
    this.setState({isPasswordConfirmationDirty: true})
  }

  render(
    {_},
    {
      confirmation,
      password,
      walletName,
      isPasswordValid,
      isPasswordDirty,
      isPasswordConfirmationDirty,
      isWalletNameValid,
      showSuccess,
    }
  ) {
    return h(
      'div',
      {class: 'content-wrapper'},
      h(
        'div',
        {class: 'margin-2rem'},
        h('h2', undefined, 'Export wallet to JSON file:'),
        h(
          'div',
          {class: 'row'},
          h('label', {for: 'keyfile-name'}, h('span', undefined, 'Choose wallet name:'))
        ),
        h('input', {
          type: 'text',
          class: 'styled-input-nodiv',
          id: 'keyfile-name',
          name: 'keyfile-name',
          placeholder: 'cardano_lite_wallet',
          value: walletName,
          onInput: this.updateWalletName,
          onBlur: this.touchPasswordField,
          autocomplete: 'off',
          ref: (element) => {
            this.walletNameField = element
          },
        }),
        h(
          'div',
          {class: 'row margin-top'},
          h('label', {for: 'keyfile-password'}, h('span', undefined, 'Password:'))
        ),
        h('input', {
          type: 'password',
          class: 'styled-input-nodiv',
          id: 'keyfile-password',
          name: 'keyfile-password',
          placeholder: 'Enter password',
          value: password,
          onInput: this.updatePassword,
          onBlur: this.touchPasswordField,
          autocomplete: 'new-password',
        }),
        h(
          'div',
          {class: 'row margin-top'},
          h(
            'label',
            {for: 'keyfile-password-confirmation'},
            h('span', undefined, 'Password confirmation:')
          )
        ),
        h('input', {
          type: 'password',
          class: 'styled-input-nodiv',
          id: 'keyfile-password-confirmation',
          name: 'keyfile-password-confirmation',
          placeholder: 'Enter password confirmation',
          value: confirmation,
          onInput: this.updatePasswordConfirmation,
          onBlur: this.touchPasswordConfirmationField,
          autocomplete: 'new-password',
        }),
        h(
          'p',
          {
            class: `validationMsg margin-top center ${
              (!isPasswordValid && isPasswordDirty && isPasswordConfirmationDirty) ||
              !isWalletNameValid
                ? ''
                : 'hidden'
            }`,
          },
          !isWalletNameValid
            ? 'The wallet name can contains only a-z, A-Z, 0-9, -, _'
            : 'Password must match confirmation and cannot be empty'
        ),
        showSuccess && h('div', {class: 'alert success'}, 'Successfully exported.'),
        h(
          'button',
          {
            disabled: !this.isPasswordValid(password, confirmation) || !isWalletNameValid,
            onClick: this.exportJsonWallet,
            onKeyDown: (e) => {
              if (e.key === 'Tab') {
                this.walletNameField.focus()
                e.preventDefault()
              }
            },
            class: 'button-like submit-button',
          },
          'Export'
        )
      )
    )
  }
}

module.exports = connect(
  undefined,
  actions
)(ExportWalletDialog)
