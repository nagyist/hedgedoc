/*
 * SPDX-FileCopyrightText: 2021 The HedgeDoc developers (see AUTHORS file)
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

describe('Autocompletion', () => {
  beforeEach(() => {
    cy.visit('/n/test')
    cy.get('.CodeMirror')
      .click()
      .get('textarea')
      .as('codeinput')
  })

  describe('code block', () => {
    it('via Enter', () => {
      cy.codemirrorFill('```')
      cy.get('.CodeMirror-hints')
        .should('exist')
      cy.get('@codeinput')
        .type('{enter}')
      cy.get('.CodeMirror-hints')
        .should('not.exist')
      cy.get('.CodeMirror-code > div:nth-of-type(1) > .CodeMirror-line > span > span')
        .should('have.text', '```abnf')
      cy.get('.CodeMirror-code > div:nth-of-type(3) > .CodeMirror-line > span  span')
        .should('have.text', '```')
      cy.getMarkdownBody()
        .find('pre > code')
        .should('exist')
    })
    it('via doubleclick', () => {
      cy.codemirrorFill('```')
      cy.get('.CodeMirror-hints > li')
        .first()
        .dblclick()
      cy.get('.CodeMirror-hints')
        .should('not.exist')
      cy.get('.CodeMirror-code > div:nth-of-type(1) > .CodeMirror-line > span > span')
        .should('have.text', '```abnf')
      cy.get('.CodeMirror-code > div:nth-of-type(3) > .CodeMirror-line > span  span')
        .should('have.text', '```')
      cy.getMarkdownBody()
        .find('pre > code')
        .should('exist')
    })
  })

  describe('container', () => {
    it('via Enter', () => {
      cy.codemirrorFill(':::')
      cy.get('.CodeMirror-hints')
        .should('exist')
      cy.get('@codeinput')
        .type('{enter}')
      cy.get('.CodeMirror-hints')
        .should('not.exist')
      cy.get('.CodeMirror-code > div:nth-of-type(1) > .CodeMirror-line > span > span')
        .should('have.text', ':::success')
      cy.get('.CodeMirror-code > div:nth-of-type(3) > .CodeMirror-line > span  span')
        .should('have.text', '::: ')
      cy.getMarkdownBody()
        .find('div.alert')
        .should('exist')
    })
    it('via doubleclick', () => {
      cy.codemirrorFill(':::')
      cy.get('.CodeMirror-hints > li')
        .first()
        .dblclick()
      cy.get('.CodeMirror-hints')
        .should('not.exist')
      cy.get('.CodeMirror-code > div:nth-of-type(1) > .CodeMirror-line > span > span')
        .should('have.text', ':::success')
      cy.get('.CodeMirror-code > div:nth-of-type(3) > .CodeMirror-line > span  span')
        .should('have.text', '::: ')
      cy.getMarkdownBody()
        .find('div.alert')
        .should('exist')
    })
  })

  describe('emoji', () => {
    describe('normal emoji', () => {
      it('via Enter', () => {
        cy.codemirrorFill(':hedg')
        cy.get('.CodeMirror-hints')
          .should('exist')
        cy.get('@codeinput')
          .type('{enter}')
        cy.get('.CodeMirror-hints')
          .should('not.exist')
        cy.get('.CodeMirror-activeline > .CodeMirror-line > span')
          .should('have.text', ':hedgehog:')
        cy.getMarkdownBody()
          .should('have.text', '🦔')
      })
      it('via doubleclick', () => {
        cy.codemirrorFill(':hedg')
        cy.get('.CodeMirror-hints > li')
          .first()
          .dblclick()
        cy.get('.CodeMirror-hints')
          .should('not.exist')
        cy.get('.CodeMirror-activeline > .CodeMirror-line > span')
          .should('have.text', ':hedgehog:')
        cy.getMarkdownBody()
          .should('have.text', '🦔')
      })
    })

    describe('fork-awesome-icon', () => {
      it('via Enter', () => {
        cy.codemirrorFill(':fa-face')
        cy.get('.CodeMirror-hints')
          .should('exist')
        cy.get('@codeinput')
          .type('{enter}')
        cy.get('.CodeMirror-hints')
          .should('not.exist')
        cy.get('.CodeMirror-activeline > .CodeMirror-line > span')
          .should('have.text', ':fa-facebook:')
        cy.getMarkdownBody()
          .find('p > i.fa.fa-facebook')
          .should('exist')
      })
      it('via doubleclick', () => {
        cy.codemirrorFill(':fa-face')
        cy.get('.CodeMirror-hints > li')
          .first()
          .dblclick()
        cy.get('.CodeMirror-hints')
          .should('not.exist')
        cy.get('.CodeMirror-activeline > .CodeMirror-line > span')
          .should('have.text', ':fa-facebook:')
        cy.getMarkdownBody()
          .find('p > i.fa.fa-facebook')
          .should('exist')
      })
    })
  })

  describe('header', () => {
    it('via Enter', () => {
      cy.codemirrorFill('#')
      cy.get('.CodeMirror-hints')
        .should('exist')
      cy.get('@codeinput')
        .type('{enter}')
      cy.get('.CodeMirror-hints')
        .should('not.exist')
      cy.get('.CodeMirror-activeline > .CodeMirror-line > span')
        .should('have.text', '# ')
      cy.getMarkdownBody()
        .find('h1 ')
        .should('have.text', ' ')
    })
    it('via doubleclick', () => {
      cy.codemirrorFill('#')
      cy.get('.CodeMirror-hints > li')
        .first()
        .dblclick()
      cy.get('.CodeMirror-hints')
        .should('not.exist')
      cy.get('.CodeMirror-activeline > .CodeMirror-line > span')
        .should('have.text', '# ')
      cy.getMarkdownBody()
        .find('h1')
        .should('have.text', ' ')
    })
  })

  describe('images', () => {
    it('via Enter', () => {
      cy.codemirrorFill('!')
      cy.get('.CodeMirror-hints')
        .should('exist')
      cy.get('@codeinput')
        .type('{enter}')
      cy.get('.CodeMirror-hints')
        .should('not.exist')
      cy.get('.CodeMirror-activeline > .CodeMirror-line > span')
        .should('have.text', '![image alt](https:// "title")')
      cy.getMarkdownBody()
        .find('p > img')
        .should('have.attr', 'alt', 'image alt')
        .should('have.attr', 'src', 'https://')
        .should('have.attr', 'title', 'title')
    })
    it('via doubleclick', () => {
      cy.codemirrorFill('!')
      cy.get('.CodeMirror-hints > li')
        .first()
        .dblclick()
      cy.get('.CodeMirror-hints')
        .should('not.exist')
      cy.get('.CodeMirror-activeline > .CodeMirror-line > span')
        .should('have.text', '![image alt](https:// "title")')
      cy.getMarkdownBody()
        .find('p > img')
        .should('have.attr', 'alt', 'image alt')
        .should('have.attr', 'src', 'https://')
        .should('have.attr', 'title', 'title')
    })
  })

  describe('links', () => {
    it('via Enter', () => {
      cy.codemirrorFill('[')
      cy.get('.CodeMirror-hints')
        .should('exist')
      cy.get('@codeinput')
        .type('{enter}')
      cy.get('.CodeMirror-hints')
        .should('not.exist')
      cy.get('.CodeMirror-activeline > .CodeMirror-line > span')
        .should('have.text', '[link text](https:// "title") ')
      cy.getMarkdownBody()
        .find('p > a')
        .should('have.text', 'link text')
        .should('have.attr', 'href', 'https://')
        .should('have.attr', 'title', 'title')
    })
    it('via doubleclick', () => {
      cy.codemirrorFill('[')
      cy.get('.CodeMirror-hints > li')
        .first()
        .dblclick()
      cy.get('.CodeMirror-hints')
        .should('not.exist')
      cy.get('.CodeMirror-activeline > .CodeMirror-line > span')
        .should('have.text', '[link text](https:// "title") ')
      cy.getMarkdownBody()
        .find('p > a')
        .should('have.text', 'link text')
        .should('have.attr', 'href', 'https://')
        .should('have.attr', 'title', 'title')
    })
  })

  describe('pdf', () => {
    it('via Enter', () => {
      cy.codemirrorFill('{')
      cy.get('.CodeMirror-hints')
        .should('exist')
      cy.get('@codeinput')
        .type('{enter}')
      cy.get('.CodeMirror-hints')
        .should('not.exist')
      cy.get('.CodeMirror-activeline > .CodeMirror-line > span')
        .should('have.text', '{%pdf https:// %}')
      cy.getMarkdownBody()
        .find('p')
        .should('exist')
    })
    it('via doubleclick', () => {
      cy.codemirrorFill('{')
      cy.get('.CodeMirror-hints > li')
        .first()
        .dblclick()
      cy.get('.CodeMirror-hints')
        .should('not.exist')
      cy.get('.CodeMirror-activeline > .CodeMirror-line > span')
        .should('have.text', '{%pdf https:// %}')
      cy.getMarkdownBody()
        .find('p')
        .should('exist')
    })
  })

  describe('collapsable blocks', () => {
    it('via Enter', () => {
      cy.codemirrorFill('<d')
      cy.get('.CodeMirror-hints')
        .should('exist')
      cy.get('@codeinput')
        .type('{enter}')
      cy.get('.CodeMirror-hints')
        .should('not.exist')
      cy.get('.CodeMirror-activeline > .CodeMirror-line > span')
        .should('have.text', '</details>') // after selecting the hint, the last line of the inserted suggestion is active
      cy.getMarkdownBody()
        .find('details')
        .should('exist')
    })
    it('via doubleclick', () => {
      cy.codemirrorFill('<d')
      cy.get('.CodeMirror-hints > li')
        .first()
        .dblclick()
      cy.get('.CodeMirror-hints')
        .should('not.exist')
      cy.get('.CodeMirror-activeline > .CodeMirror-line > span')
        .should('have.text', '</details>')
      cy.getMarkdownBody()
        .find('details')
        .should('exist')
    })
  })
})
