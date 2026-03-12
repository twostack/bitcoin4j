package org.twostack.bitcoin4j.script;

import org.twostack.bitcoin4j.script.templates.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Singleton registry for script templates. Registers all known templates and provides
 * lookup by name and pattern-based script identification.
 */
public class ScriptTemplateRegistry {

    private static final ScriptTemplateRegistry INSTANCE = new ScriptTemplateRegistry();

    private final Map<String, ScriptTemplate> templates = new LinkedHashMap<>();

    private ScriptTemplateRegistry() {
        // Register all built-in templates.
        // Order matters for identifyScript — more specific templates should come first.
        register(new AuthorIdentityTemplate());
        register(new BProtocolTemplate());
        register(new HodlockerTemplate());
        register(new P2PKHTemplate());
        register(new P2PKTemplate());
        register(new P2MSTemplate());
        register(new P2SHTemplate());
        register(new OpReturnTemplate());
    }

    public static ScriptTemplateRegistry getInstance() {
        return INSTANCE;
    }

    /**
     * Registers a template. If a template with the same name already exists, it is replaced.
     */
    public void register(ScriptTemplate template) {
        templates.put(template.getName(), template);
    }

    /**
     * Returns the template with the given name, or null if not found.
     */
    public ScriptTemplate getTemplate(String name) {
        return templates.get(name);
    }

    /**
     * Returns all registered templates.
     */
    public List<ScriptTemplate> getAllTemplates() {
        return new ArrayList<>(templates.values());
    }

    /**
     * Iterates through registered templates and returns the first one that matches the script.
     * Returns null if no template matches.
     */
    public ScriptTemplate identifyScript(Script script) {
        for (ScriptTemplate template : templates.values()) {
            if (template.matches(script)) {
                return template;
            }
        }
        return null;
    }

    /**
     * Convenience method: identifies the script and extracts its info.
     * Returns null if no template matches.
     */
    public ScriptInfo extractScriptInfo(Script script) {
        ScriptTemplate template = identifyScript(script);
        if (template == null) {
            return null;
        }
        return template.extractScriptInfo(script);
    }
}
