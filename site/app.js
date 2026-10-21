// 官网配色两档：暗色 ⇄ 亮色。图标由 CSS 按 data-theme 切换，这里只维护可访问性文案。
(function () {
  var KEY = 'reconx-site-theme'
  var ORDER = ['dark', 'light']
  var NAME = { dark: '暗色', light: '亮色' }
  var root = document.documentElement
  var btn = document.getElementById('themeBtn')
  if (!btn) return

  function current() {
    var t = root.getAttribute('data-theme')
    return ORDER.indexOf(t) >= 0 ? t : 'dark'
  }

  function render() {
    var cur = current()
    var next = ORDER[(ORDER.indexOf(cur) + 1) % ORDER.length]
    btn.setAttribute('title', '当前：' + NAME[cur] + '，点击切换到' + NAME[next])
    btn.setAttribute('aria-label', '切换到' + NAME[next] + '配色')
  }

  var saved = null
  try { saved = localStorage.getItem(KEY) } catch (e) { /* 隐私模式下忽略 */ }
  if (saved && ORDER.indexOf(saved) >= 0) root.setAttribute('data-theme', saved)
  render()

  btn.addEventListener('click', function () {
    var next = ORDER[(ORDER.indexOf(current()) + 1) % ORDER.length]
    root.setAttribute('data-theme', next)
    try { localStorage.setItem(KEY, next) } catch (e) { /* 忽略 */ }
    render()
  })
})()
