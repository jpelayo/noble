// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import UIKit
import SwiftUI
import NobleClientCrypto

/// A tokenized text field for BIP-39 mnemonic entry.
///
/// Valid BIP-39 words become inline capsule tokens (like Mail.app "To:" field).
/// The cursor moves freely among tokens and text. Backspace deletes a token.
/// Tapping a token converts it back to editable text in place.
struct TokenizedWordField: UIViewRepresentable {
    @Binding var confirmedWords: [String]
    @Binding var errorMessage: String?
    var placeholder: String

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    func makeUIView(context: Context) -> TokenTextView {
        let view = TokenTextView()
        view.tokenDelegate = context.coordinator
        let font = UIFont.monospacedSystemFont(ofSize: 16, weight: .regular)
        let paragraphStyle = NSMutableParagraphStyle()
        paragraphStyle.lineSpacing = 10
        view.font = font
        view.typingAttributes = [
            .font: font,
            .paragraphStyle: paragraphStyle,
        ]
        view.autocorrectionType = .no
        view.autocapitalizationType = .none
        view.spellCheckingType = .no
        view.smartQuotesType = .no
        view.smartDashesType = .no
        view.returnKeyType = .next
        view.textContainerInset = UIEdgeInsets(top: 10, left: 6, bottom: 10, right: 6)
        view.backgroundColor = .clear
        view.setPlaceholder(placeholder)
        return view
    }

    func updateUIView(_ view: TokenTextView, context: Context) {
        // Only rebuild if the word list changed externally (e.g. Back button cleared it)
        if confirmedWords.isEmpty && view.tokenCount > 0 {
            view.clearAll()
            view.setPlaceholder(placeholder)
        }
    }

    // MARK: - Coordinator

    final class Coordinator: NSObject, TokenTextViewDelegate {
        var parent: TokenizedWordField

        init(_ parent: TokenizedWordField) {
            self.parent = parent
        }

        func tokenTextView(_ view: TokenTextView, shouldTokenize word: String) -> Bool {
            let lower = word.lowercased()
            if BIP39Wordlist.isValid(lower) {
                parent.errorMessage = nil
                return true
            } else {
                parent.errorMessage = "\"\(word)\" is not a valid BIP-39 word [NE-203]"
                return false
            }
        }

        func tokenTextViewDidChangeTokens(_ view: TokenTextView, words: [String]) {
            parent.confirmedWords = words
            if words.count == 24 {
                parent.errorMessage = nil
            }
        }
    }
}

// MARK: - TokenTextViewDelegate

protocol TokenTextViewDelegate: AnyObject {
    func tokenTextView(_ view: TokenTextView, shouldTokenize word: String) -> Bool
    func tokenTextViewDidChangeTokens(_ view: TokenTextView, words: [String])
}

// MARK: - TokenTextView

/// UITextView subclass that manages inline token attachments.
final class TokenTextView: UITextView, UITextViewDelegate {
    weak var tokenDelegate: TokenTextViewDelegate?
    private var placeholderLabel: UILabel?

    var tokenCount: Int {
        var count = 0
        textStorage.enumerateAttribute(.tokenWord, in: NSRange(location: 0, length: textStorage.length)) { val, _, _ in
            if val != nil { count += 1 }
        }
        return count
    }

    private var freezeWorkItem: DispatchWorkItem?
    private var isFreezing = false  // re-entrancy guard

    private var freezeTap: UITapGestureRecognizer?

    override init(frame: CGRect, textContainer: NSTextContainer?) {
        super.init(frame: frame, textContainer: textContainer)
        delegate = self
    }

    override func becomeFirstResponder() -> Bool {
        let result = super.becomeFirstResponder()
        // Add the freeze tap gesture only after the field is focused
        if result && freezeTap == nil {
            let tap = UITapGestureRecognizer(target: self, action: #selector(handleTap(_:)))
            tap.cancelsTouchesInView = false
            addGestureRecognizer(tap)
            freezeTap = tap
        }
        return result
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) not supported")
    }

    func setPlaceholder(_ text: String) {
        if placeholderLabel == nil {
            let label = UILabel()
            label.textColor = .placeholderText
            label.font = .monospacedSystemFont(ofSize: 16, weight: .regular)
            label.translatesAutoresizingMaskIntoConstraints = false
            addSubview(label)
            NSLayoutConstraint.activate([
                label.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 11),
                label.topAnchor.constraint(equalTo: topAnchor, constant: 10),
            ])
            placeholderLabel = label
        }
        placeholderLabel?.text = text
        placeholderLabel?.isHidden = textStorage.length > 0
    }

    func clearAll() {
        textStorage.replaceCharacters(in: NSRange(location: 0, length: textStorage.length), with: "")
        placeholderLabel?.isHidden = false
    }

    /// Get all token words in order.
    func allTokenWords() -> [String] {
        var words: [String] = []
        textStorage.enumerateAttribute(.tokenWord, in: NSRange(location: 0, length: textStorage.length)) { val, _, _ in
            if let word = val as? String { words.append(word) }
        }
        return words
    }

    // MARK: - Token creation

    private func makeTokenAttachment(word: String, index: Int) -> NSAttributedString {
        // Exact same font as typed text — 16pt mono regular
        let wordFont = UIFont.monospacedSystemFont(ofSize: 16, weight: .regular)
        let indexFont = UIFont.monospacedSystemFont(ofSize: 11, weight: .regular)
        let padding = UIEdgeInsets(top: 4, left: 8, bottom: 4, right: 8)
        let spacing: CGFloat = 3

        let indexStr = "\(index)."
        let indexSize = (indexStr as NSString).size(withAttributes: [.font: indexFont])
        let wordSize = (word as NSString).size(withAttributes: [.font: wordFont])

        let contentHeight = wordSize.height // word font is the dominant height
        let totalWidth = padding.left + indexSize.width + spacing + wordSize.width + padding.right
        let totalHeight = padding.top + contentHeight + padding.bottom

        let format = UIGraphicsImageRendererFormat()
        format.scale = UIScreen.main.scale
        let renderer = UIGraphicsImageRenderer(size: CGSize(width: totalWidth, height: totalHeight), format: format)
        let image = renderer.image { _ in
            let rect = CGRect(origin: .zero, size: CGSize(width: totalWidth, height: totalHeight))
            UIColor.tintColor.withAlphaComponent(0.12).setFill()
            UIBezierPath(roundedRect: rect, cornerRadius: totalHeight / 2).fill()

            // Center index vertically within content area
            let indexY = padding.top + (contentHeight - indexSize.height) / 2
            (indexStr as NSString).draw(
                at: CGPoint(x: padding.left, y: indexY),
                withAttributes: [.font: indexFont, .foregroundColor: UIColor.tertiaryLabel]
            )

            // Word sits at top of content area (same baseline as typed text)
            (word as NSString).draw(
                at: CGPoint(x: padding.left + indexSize.width + spacing, y: padding.top),
                withAttributes: [.font: wordFont, .foregroundColor: UIColor.label]
            )
        }

        let attachment = NSTextAttachment(image: image)
        // Place capsule so the word text inside aligns with typed text outside.
        // The word draws at padding.top (4pt) inside the image.
        // We want that to align with the line's ascender.
        // yOffset = -(totalHeight - wordFont.ascender - padding.top)
        let yOffset = wordFont.descender - padding.bottom
        attachment.bounds = CGRect(x: 0, y: yOffset, width: totalWidth, height: totalHeight)

        let result = NSMutableAttributedString(attachment: attachment)
        result.addAttribute(.tokenWord, value: word, range: NSRange(location: 0, length: result.length))
        return result
    }

    private func tokenize(word: String) {
        let index = allTokenWords().count + 1
        let tokenAttr = makeTokenAttachment(word: word.lowercased(), index: index)

        // Insert token at current cursor position (replace trailing text)
        let cursorPos = selectedRange.location

        // Find the start of the current word (scan backwards from cursor for non-attachment text)
        var wordStart = cursorPos
        while wordStart > 0 {
            let prevChar = textStorage.attributedSubstring(from: NSRange(location: wordStart - 1, length: 1))
            if prevChar.attribute(.tokenWord, at: 0, effectiveRange: nil) != nil {
                break
            }
            let char = (prevChar.string as NSString).character(at: 0)
            if CharacterSet.whitespacesAndNewlines.contains(Unicode.Scalar(char)!) {
                break
            }
            wordStart -= 1
        }

        let replaceRange = NSRange(location: wordStart, length: cursorPos - wordStart)
        textStorage.replaceCharacters(in: replaceRange, with: tokenAttr)

        // Add a space after the token
        let spaceAttr = NSAttributedString(string: " ", attributes: [
            .font: self.font ?? .systemFont(ofSize: 16)
        ])
        textStorage.insert(spaceAttr, at: wordStart + tokenAttr.length)

        selectedRange = NSRange(location: wordStart + tokenAttr.length + 1, length: 0)
        let ps = NSMutableParagraphStyle(); ps.lineSpacing = 10
        typingAttributes = [.font: UIFont.monospacedSystemFont(ofSize: 16, weight: .regular), .paragraphStyle: ps]
        notifyTokensChanged()
    }

    private func notifyTokensChanged() {
        tokenDelegate?.tokenTextViewDidChangeTokens(self, words: allTokenWords())
        placeholderLabel?.isHidden = textStorage.length > 0
    }

    // MARK: - Renumber tokens

    private func renumberAllTokens() {
        // Collect token ranges first, then mutate (avoid mutating during enumeration)
        var tokens: [(word: String, range: NSRange)] = []
        textStorage.enumerateAttribute(.tokenWord, in: NSRange(location: 0, length: textStorage.length), options: []) { val, range, _ in
            if let word = val as? String {
                tokens.append((word, range))
            }
        }
        // Replace right-to-left to preserve ranges
        for (idx, entry) in tokens.enumerated().reversed() {
            let newToken = makeTokenAttachment(word: entry.word, index: idx + 1)
            textStorage.replaceCharacters(in: entry.range, with: newToken)
        }
    }

    // MARK: - UITextViewDelegate

    func textView(_ textView: UITextView, shouldChangeTextIn range: NSRange, replacementText text: String) -> Bool {
        // User is typing — cancel any pending tap-freeze
        freezeWorkItem?.cancel()

        // Enter / Return → try tokenize
        if text == "\n" {
            tryTokenizeCurrentWord()
            return false
        }

        // Space or Tab → try tokenize
        if text == " " || text == "\t" {
            tryTokenizeCurrentWord()
            return false
        }

        // Backspace on a token → delete it, keep cursor in place
        if text.isEmpty && range.length == 1 {
            let attr = textStorage.attribute(.tokenWord, at: range.location, effectiveRange: nil)
            if attr != nil {
                let pos = range.location
                textStorage.replaceCharacters(in: range, with: "")
                renumberAllTokens()
                notifyTokensChanged()
                selectedRange = NSRange(location: min(pos, textStorage.length), length: 0)
                return false
            }
        }

        // Paste: multi-character text containing spaces → insert then freeze
        if text.count > 1 && text.rangeOfCharacter(from: .whitespacesAndNewlines) != nil {
            let attrText = NSAttributedString(string: text, attributes: [.font: self.font ?? .systemFont(ofSize: 16)])
            textStorage.replaceCharacters(in: range, with: attrText)
            selectedRange = NSRange(location: range.location + text.count, length: 0)
            tokenizeAllPlainText()
            return false
        }

        // Normal character — force correct font before insertion
        let ps = NSMutableParagraphStyle(); ps.lineSpacing = 10
        typingAttributes = [.font: UIFont.monospacedSystemFont(ofSize: 16, weight: .regular), .paragraphStyle: ps]
        return true
    }

    func textViewDidChange(_ textView: UITextView) {
        placeholderLabel?.isHidden = textStorage.length > 0
        // Keep typing attributes locked
        let ps = NSMutableParagraphStyle(); ps.lineSpacing = 10
        typingAttributes = [.font: UIFont.monospacedSystemFont(ofSize: 16, weight: .regular), .paragraphStyle: ps]
    }

    func textViewDidChangeSelection(_ textView: UITextView) {
        // No automatic freezing here — only on explicit triggers.
    }

    /// Tap schedules a freeze after a short delay. If the user starts typing
    /// within that window, the freeze is cancelled — they were just positioning
    /// the cursor to type. If no typing follows, it's a deliberate reposition
    /// and pending text gets frozen.
    @objc private func handleTap(_ gesture: UITapGestureRecognizer) {
        // First tap focuses the field — don't freeze, let the keyboard appear.
        // Only freeze on taps when already editing and there's text to freeze.
        guard isFirstResponder, hasPlainText() else { return }
        freezeWorkItem?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard let self, self.isFirstResponder, self.hasPlainText() else { return }
            self.tokenizeAllPlainText()
        }
        freezeWorkItem = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4, execute: work)
    }

    /// Returns true if there is any non-token, non-whitespace text in the storage.
    private func hasPlainText() -> Bool {
        for pos in 0..<textStorage.length {
            if textStorage.attribute(.tokenWord, at: pos, effectiveRange: nil) == nil {
                let ch = (textStorage.string as NSString).substring(with: NSRange(location: pos, length: 1))
                if ch.rangeOfCharacter(from: .whitespacesAndNewlines) == nil {
                    return true
                }
            }
        }
        return false
    }

    /// Scan the entire text storage for plain-text words and tokenize valid ones.
    private func tokenizeAllPlainText() {
        guard !isFreezing else { return }
        isFreezing = true
        defer { isFreezing = false }

        let fullText = textStorage.string
        guard !fullText.isEmpty else { return }
        guard hasPlainText() else { return }

        // Collect all plain-text (non-token) segments with their ranges
        var segments: [(word: String, range: NSRange)] = []
        var i = 0
        while i < textStorage.length {
            var effectiveRange = NSRange()
            let attr = textStorage.attribute(.tokenWord, at: i, effectiveRange: &effectiveRange)
            if attr != nil {
                // Token — skip it
                i = effectiveRange.upperBound
            } else {
                // Plain text — extract the character
                i += 1
            }
        }

        // Simpler approach: extract all plain text, find words, tokenize them right-to-left
        // to avoid index shifting issues
        var plainWords: [(word: String, range: NSRange)] = []
        var currentWord = ""
        var currentStart = -1

        for pos in 0..<textStorage.length {
            let attr = textStorage.attribute(.tokenWord, at: pos, effectiveRange: nil)
            if attr != nil {
                // Hit a token — flush current word
                if !currentWord.isEmpty {
                    plainWords.append((currentWord, NSRange(location: currentStart, length: pos - currentStart)))
                    currentWord = ""
                    currentStart = -1
                }
                continue
            }
            let char = (textStorage.string as NSString).substring(with: NSRange(location: pos, length: 1))
            if char.rangeOfCharacter(from: .whitespacesAndNewlines) != nil {
                // Whitespace — flush current word
                if !currentWord.isEmpty {
                    plainWords.append((currentWord, NSRange(location: currentStart, length: pos - currentStart)))
                    currentWord = ""
                    currentStart = -1
                }
            } else {
                if currentStart == -1 { currentStart = pos }
                currentWord += char
            }
        }
        if !currentWord.isEmpty && currentStart >= 0 {
            plainWords.append((currentWord, NSRange(location: currentStart, length: textStorage.length - currentStart)))
        }

        // Process right-to-left (so ranges don't shift).
        // Valid BIP-39 → tokenize. Invalid → delete as dust.
        var didChange = false
        for entry in plainWords.reversed() {
            let lower = entry.word.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard !lower.isEmpty else { continue }
            if tokenDelegate?.tokenTextView(self, shouldTokenize: lower) == true {
                let index = allTokenWords().count + 1 // will be renumbered
                let tokenAttr = makeTokenAttachment(word: lower, index: index)
                textStorage.replaceCharacters(in: entry.range, with: tokenAttr)
                didChange = true
            } else {
                // Not a valid BIP-39 word — remove as dust
                textStorage.replaceCharacters(in: entry.range, with: "")
                didChange = true
            }
        }

        if didChange {
            cleanUpWhitespace()
            renumberAllTokens()
            notifyTokensChanged()
            // Keep cursor within bounds, don't move it to the end
            let pos = min(selectedRange.location, textStorage.length)
            selectedRange = NSRange(location: pos, length: 0)
        }
    }

    /// Remove leading/trailing/double whitespace between tokens.
    private func cleanUpWhitespace() {
        let text = textStorage.string
        // Remove leading whitespace
        while textStorage.length > 0 {
            let first = (textStorage.string as NSString).substring(with: NSRange(location: 0, length: 1))
            if first.rangeOfCharacter(from: .whitespacesAndNewlines) != nil
                && textStorage.attribute(.tokenWord, at: 0, effectiveRange: nil) == nil {
                textStorage.replaceCharacters(in: NSRange(location: 0, length: 1), with: "")
            } else {
                break
            }
        }
        // Collapse double spaces
        var pos = 0
        while pos < textStorage.length - 1 {
            let c1 = (textStorage.string as NSString).substring(with: NSRange(location: pos, length: 1))
            let c2 = (textStorage.string as NSString).substring(with: NSRange(location: pos + 1, length: 1))
            if c1 == " " && c2 == " "
                && textStorage.attribute(.tokenWord, at: pos, effectiveRange: nil) == nil
                && textStorage.attribute(.tokenWord, at: pos + 1, effectiveRange: nil) == nil {
                textStorage.replaceCharacters(in: NSRange(location: pos + 1, length: 1), with: "")
            } else {
                pos += 1
            }
        }
    }

    /// Attempt to tokenize the plain-text word immediately before the cursor.
    private func tryTokenizeCurrentWord() {
        tokenizeAllPlainText()
    }

    /// Tokenize on losing focus (tap outside).
    override func resignFirstResponder() -> Bool {
        tokenizeAllPlainText()
        return super.resignFirstResponder()
    }
}

// MARK: - Custom attribute key

private extension NSAttributedString.Key {
    static let tokenWord = NSAttributedString.Key("noble.tokenWord")
}
