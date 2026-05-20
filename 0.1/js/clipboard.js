  document$.subscribe(() => {
    document.querySelectorAll('.md-code__button').forEach(btn => {
      const pre = btn.closest('.highlight')?.querySelector('code')
      if (!pre) return
      btn.addEventListener('click', e => {
        const lines = pre.innerText.split('\n')
          .filter(l => l.startsWith('$ '))
          .map(l => l.slice(2))
          .join('\n')
        if (lines) { e.stopPropagation(); navigator.clipboard.writeText(lines) }
      }, true)
    })
  })  
