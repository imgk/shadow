package suffixtree

import (
	"strings"
	"sync"
)

type Tree struct {
	*node
	sep string
	sync.RWMutex
}
type node struct {
	value  string
	branch map[string]*node
}

func NewTree(sep string) *Tree {
	return &Tree{
		node: &node{
			value:  "",
			branch: map[string]*node{},
		},
		sep:     sep,
		RWMutex: sync.RWMutex{},
	}
}

func (t *Tree) Store(k string, v string) {
	t.Lock()
	defer t.Unlock()
	t.store(strings.Split(strings.TrimSuffix(k, t.sep), t.sep), v)
}
func (n *node) store(ks []string, v string) {
	l := len(ks)
	switch l {
	case 0:
		return
	case 1:
		k := ks[l-1]

		if k == "*" || k == "**" {
			n.value = v
		}

		b, ok := n.branch[k]
		if ok {
			b.value = v
			return
		}

		n.branch[k] = &node{
			value:  v,
			branch: map[string]*node{},
		}
	default:
		k := ks[l-1]

		b, ok := n.branch[k]
		if !ok {
			b = &node{
				value:  "",
				branch: map[string]*node{},
			}
			n.branch[k] = b
		}

		b.store(ks[:l-1], v)
	}
}

func (t *Tree) Load(k string) string {
	t.RLock()
	defer t.RUnlock()
	return t.load(strings.Split(strings.TrimSuffix(k, t.sep), t.sep))
}
func (n *node) load(ks []string) string {
	l := len(ks)
	switch l {
	case 0:
		return ""
	case 1:
		b, ok := n.branch[ks[l-1]]
		if ok {
			return b.value
		}

		b, ok = n.branch["*"]
		if ok {
			return b.value
		}

		b, ok = n.branch["**"]
		if ok {
			return b.value
		}

		return ""
	default:
		b, ok := n.branch[ks[l-1]]
		if ok {
			s := b.load(ks[:l-1])
			if s != "" {
				return s
			}
		}

		b, ok = n.branch["*"]
		if ok {
			s := b.load(ks[:l-1])
			if s != "" {
				return s
			}
		}

		b, ok = n.branch["**"]
		if ok {
			return b.value
		}

		return ""
	}
}
