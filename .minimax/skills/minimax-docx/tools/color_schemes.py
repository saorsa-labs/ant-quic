"""
Color Schemes - Python version synced from templates/ColorSchemes.cs

IMPORTANT DESIGN RULES FOR AGENT:
1. Text.* colors are for ALL text content - ALWAYS low saturation for readability
2. Decorative.Muted.* - low saturation decorative colors (subtle headers, professional look)
3. Decorative.Vibrant.* - high saturation decorative colors (eye-catching, bold designs)
4. NEVER use Decorative.Vibrant colors for text - damages readability
5. Choose Muted vs Vibrant based on document style (formal=Muted, promotional=Vibrant)

Structure per scheme:
  Text.Primary   - Main headings (low saturation, good contrast)
  Text.Secondary - Subheadings (low saturation)
  Text.Body      - Body text (low saturation, high readability)
  Text.Muted     - Captions, helper text (low saturation, lighter)

  Decorative.Muted.Primary/Secondary/Accent   - Subtle decorative elements
  Decorative.Vibrant.Primary/Secondary/Accent - Bold decorative elements

  UI.Border      - Table/box borders
  UI.TableHeader - Table header background

Usage:
    from color_schemes import SCHEMES

    scheme = SCHEMES['Morandi']
    heading_color = scheme['Text']['Primary']        # For headings
    body_color = scheme['Text']['Body']              # For body text
    header_fill = scheme['Decorative']['Muted']['Primary']  # Subtle header
    bold_accent = scheme['Decorative']['Vibrant']['Accent'] # Eye-catching accent
"""

# ============================================================================
# Morandi - Soft muted tones, artistic and editorial
# ============================================================================
Morandi = {
    'Text': {
        'Primary': '2d3a35',
        'Secondary': '4a5750',
        'Body': '5a6b62',
        'Muted': '8a9a90',
    },
    'Decorative': {
        'Muted': {
            'Primary': '7C9885',
            'Secondary': '8B9DC3',
            'Accent': '9CAF88',
        },
        'Vibrant': {
            'Primary': '5A8066',
            'Secondary': '6B7FB0',
            'Accent': '7A9A60',
        },
    },
    'UI': {
        'Border': 'd8e0dc',
        'TableHeader': 'f0f4f2',
    },
}

# ============================================================================
# InkWash - Gray zen tones, traditional and contemplative
# ============================================================================
InkWash = {
    'Text': {
        'Primary': '1A202C',
        'Secondary': '2D3748',
        'Body': '4A5568',
        'Muted': 'A0AEC0',
    },
    'Decorative': {
        'Muted': {
            'Primary': '4A5568',
            'Secondary': '718096',
            'Accent': 'A0AEC0',
        },
        'Vibrant': {
            'Primary': '3A4558',
            'Secondary': '5A6A80',
            'Accent': '8090A0',
        },
    },
    'UI': {
        'Border': 'CBD5E0',
        'TableHeader': 'EDF2F7',
    },
}

# ============================================================================
# Corporate - Professional business blue
# ============================================================================
Corporate = {
    'Text': {
        'Primary': '1A1A2E',
        'Secondary': '2E3A50',
        'Body': '3D5A80',
        'Muted': '8FA8C8',
    },
    'Decorative': {
        'Muted': {
            'Primary': '3D5A80',
            'Secondary': '6A8AA4',
            'Accent': '8AACBE',
        },
        'Vibrant': {
            'Primary': '1E3A5F',
            'Secondary': '4A90A4',
            'Accent': '2E7090',
        },
    },
    'UI': {
        'Border': 'C4D4E0',
        'TableHeader': 'E8EEF4',
    },
}

# ============================================================================
# Earth - Brown and olive, natural and organic
# ============================================================================
Earth = {
    'Text': {
        'Primary': '3D3229',
        'Secondary': '4D4239',
        'Body': '5D4E42',
        'Muted': '9A8B7A',
    },
    'Decorative': {
        'Muted': {
            'Primary': '6B5B4F',
            'Secondary': '8B7355',
            'Accent': 'A08060',
        },
        'Vibrant': {
            'Primary': '8B6040',
            'Secondary': 'A67B5B',
            'Accent': 'C08050',
        },
    },
    'UI': {
        'Border': 'D4C8BC',
        'TableHeader': 'F2EDE8',
    },
}

# ============================================================================
# Nordic - Cool gray and misty blue, minimalist and tech
# ============================================================================
Nordic = {
    'Text': {
        'Primary': '2C3E4A',
        'Secondary': '3A4E5A',
        'Body': '4A6572',
        'Muted': '8A9EA8',
    },
    'Decorative': {
        'Muted': {
            'Primary': '5A7080',
            'Secondary': '7A909A',
            'Accent': '90A8B0',
        },
        'Vibrant': {
            'Primary': '4A5D6B',
            'Secondary': '6B8E9B',
            'Accent': '5080A0',
        },
    },
    'UI': {
        'Border': 'C8D4DA',
        'TableHeader': 'ECF0F3',
    },
}

# ============================================================================
# French - Off-white and dusty pink, luxury and feminine
# ============================================================================
French = {
    'Text': {
        'Primary': '4A3F3F',
        'Secondary': '5A4848',
        'Body': '6B5858',
        'Muted': 'A89898',
    },
    'Decorative': {
        'Muted': {
            'Primary': '9E7B7B',
            'Secondary': 'B8A9A9',
            'Accent': 'C4B0B0',
        },
        'Vibrant': {
            'Primary': 'C08080',
            'Secondary': 'D4A0A0',
            'Accent': 'E0B0B0',
        },
    },
    'UI': {
        'Border': 'DDD4D4',
        'TableHeader': 'F5F0F0',
    },
}

# ============================================================================
# Academic - Navy and burgundy, research and education
# ============================================================================
Academic = {
    'Text': {
        'Primary': '1A252F',
        'Secondary': '2A3540',
        'Body': '4A5A6A',
        'Muted': '8A9AA8',
    },
    'Decorative': {
        'Muted': {
            'Primary': '4A5A70',
            'Secondary': '6A4A4A',
            'Accent': '7A6050',
        },
        'Vibrant': {
            'Primary': '2C3E50',
            'Secondary': '8B3030',
            'Accent': 'A06030',
        },
    },
    'UI': {
        'Border': 'D4D8DC',
        'TableHeader': 'F5F5F0',
    },
}

# ============================================================================
# Ocean - Misty blue and sand, marine and wellness
# ============================================================================
Ocean = {
    'Text': {
        'Primary': '2A4A5A',
        'Secondary': '3A5A6A',
        'Body': '4A6A7A',
        'Muted': '8A9AA8',
    },
    'Decorative': {
        'Muted': {
            'Primary': '6A8A9A',
            'Secondary': '8AAAB0',
            'Accent': 'A0C0C4',
        },
        'Vibrant': {
            'Primary': '4080A0',
            'Secondary': '60B0C0',
            'Accent': '40A0B0',
        },
    },
    'UI': {
        'Border': 'C8DDE4',
        'TableHeader': 'EEF4F6',
    },
}

# ============================================================================
# Forest - Olive and moss green, nature and sustainability
# ============================================================================
Forest = {
    'Text': {
        'Primary': '2A3A2A',
        'Secondary': '3A4A3A',
        'Body': '4A5A3A',
        'Muted': '8A9A7A',
    },
    'Decorative': {
        'Muted': {
            'Primary': '5A6B4A',
            'Secondary': '7A8B5A',
            'Accent': '8B9B6A',
        },
        'Vibrant': {
            'Primary': '4A7040',
            'Secondary': '60A050',
            'Accent': '70B060',
        },
    },
    'UI': {
        'Border': 'C8D4C4',
        'TableHeader': 'EEF2EC',
    },
}

# ============================================================================
# Industrial - Charcoal and rust, manufacturing and engineering
# ============================================================================
Industrial = {
    'Text': {
        'Primary': '2D2D2D',
        'Secondary': '3D3D3D',
        'Body': '5A5A5A',
        'Muted': '8A8A8A',
    },
    'Decorative': {
        'Muted': {
            'Primary': '5A5A5A',
            'Secondary': '7A6A5A',
            'Accent': '8A7A60',
        },
        'Vibrant': {
            'Primary': '4A4A4A',
            'Secondary': 'A07050',
            'Accent': 'C08040',
        },
    },
    'UI': {
        'Border': 'C8C8C8',
        'TableHeader': 'EBEBEB',
    },
}

# ============================================================================
# Desert - Ochre and sandy gold, warm and regional
# ============================================================================
Desert = {
    'Text': {
        'Primary': '4A3A2A',
        'Secondary': '5A4A3A',
        'Body': '7A6A4A',
        'Muted': 'A89A7A',
    },
    'Decorative': {
        'Muted': {
            'Primary': '907050',
            'Secondary': 'A89070',
            'Accent': 'C0A080',
        },
        'Vibrant': {
            'Primary': 'C08040',
            'Secondary': 'D4A060',
            'Accent': 'E0B070',
        },
    },
    'UI': {
        'Border': 'DDD4C4',
        'TableHeader': 'F5F0E8',
    },
}

# ============================================================================
# RedPower - Authoritative and solemn, for Party/Government documents
# Use case: Government reports, Party propaganda, Official notices
# WARNING: Vibrant red is for decorative use ONLY - never for body text!
# ============================================================================
RedPower = {
    'Text': {
        'Primary': '2B1212',     # Deep warm black - main headings
        'Secondary': '3B2222',   # Dark brown - subheadings
        'Body': '594949',        # Warm grey - body text
        'Muted': '9E8888',       # Muted mauve - captions
    },
    'Decorative': {
        'Muted': {
            'Primary': '8B4040',     # Muted red - subtle headers
            'Secondary': 'A08060',   # Muted gold - subtle lines
            'Accent': 'D8C8B0',      # Pale cream - fills
        },
        'Vibrant': {
            'Primary': 'B82525',     # China Red - bold headers
            'Secondary': 'CFA972',   # Gold - decorative lines
            'Accent': 'D42020',      # Bright red - accents
        },
    },
    'UI': {
        'Border': 'E6C7C7',
        'TableHeader': 'FFF5F5',
    },
}

# ============================================================================
# Luxury - Black and Gold, high-end and exclusive
# Use case: Fine dining menus, VIP invitations, Real Estate brochures
# ============================================================================
Luxury = {
    'Text': {
        'Primary': '000000',     # Pure black - headings
        'Secondary': '1A1A1A',   # Rich black - subheadings
        'Body': '4A4A4A',        # Dark grey - body
        'Muted': '8C8C8C',       # Silver grey - captions
    },
    'Decorative': {
        'Muted': {
            'Primary': '3A3A3A',     # Soft black - frames
            'Secondary': '9A8050',   # Muted gold - borders
            'Accent': 'C8B890',      # Pale gold - fills
        },
        'Vibrant': {
            'Primary': '1A1A1A',     # Rich black - frames
            'Secondary': 'C5A059',   # Metallic gold - borders
            'Accent': 'D4AF37',      # Bright gold - highlights
        },
    },
    'UI': {
        'Border': 'DECBA5',
        'TableHeader': 'FAF8F5',
    },
}

# ============================================================================
# Vibrant - High energy yellow and black, bold and loud
# Use case: Recruitment flyers, Sale posters, Gym promos
# WARNING: Yellow is for backgrounds/shapes ONLY - use black text for readability!
# ============================================================================
Vibrant = {
    'Text': {
        'Primary': '000000',     # Black - all headings
        'Secondary': '1A1A1A',   # Near black - subheadings
        'Body': '404040',        # Dark grey - body text
        'Muted': '666666',       # Medium grey - captions
    },
    'Decorative': {
        'Muted': {
            'Primary': 'C0A820',     # Muted yellow - subtle
            'Secondary': '3A3A3A',   # Dark grey - subtle contrast
            'Accent': 'A09020',      # Olive yellow - accents
        },
        'Vibrant': {
            'Primary': 'FFD700',     # Electric yellow - backgrounds
            'Secondary': '000000',   # Black - contrast shapes
            'Accent': 'FFC000',      # Gold yellow - accents
        },
    },
    'UI': {
        'Border': 'E6C200',
        'TableHeader': 'FFFFE0',
    },
}

# ============================================================================
# Innovation - Electric purple and indigo, modern SaaS and Tech
# Use case: Software whitepapers, Tech conferences, Startup pitch decks
# WARNING: Vibrant purple for buttons/shapes - use desaturated colors for text!
# ============================================================================
Innovation = {
    'Text': {
        'Primary': '1E1B4B',     # Deep indigo - headings
        'Secondary': '312E81',   # Dark purple - subheadings
        'Body': '4A4766',        # Muted purple-grey - body
        'Muted': '8A88A0',       # Grey lavender - captions
    },
    'Decorative': {
        'Muted': {
            'Primary': '5A5090',     # Muted indigo - subtle
            'Secondary': '7060A0',   # Muted violet - subtle
            'Accent': 'A0A0C0',      # Grey purple - fills
        },
        'Vibrant': {
            'Primary': '4F46E5',     # Indigo - header bars
            'Secondary': '7C3AED',   # Violet - buttons
            'Accent': '8B5CF6',      # Purple - highlights
        },
    },
    'UI': {
        'Border': 'E0E7FF',
        'TableHeader': 'F5F3FF',
    },
}

# ============================================================================
# Clinical - Clean teal and sterile white, medical and hygiene
# Use case: Hospital reports, Health checkups, Pharmaceutical guides
# WARNING: Bright teal for decorative only - text must be dark and readable!
# ============================================================================
Clinical = {
    'Text': {
        'Primary': '1A3A38',     # Very dark teal - headings
        'Secondary': '2A4A48',   # Dark teal - subheadings
        'Body': '3A5A58',        # Muted teal - body
        'Muted': '6A8A88',       # Grey teal - captions
    },
    'Decorative': {
        'Muted': {
            'Primary': '4A7A70',     # Muted teal - subtle
            'Secondary': '6A9A90',   # Soft teal - subtle
            'Accent': '90B0A8',      # Grey teal - fills
        },
        'Vibrant': {
            'Primary': '00897B',     # Teal - header bars
            'Secondary': '26A69A',   # Light teal - accents
            'Accent': '00BFA5',      # Bright teal - highlights
        },
    },
    'UI': {
        'Border': 'B2DFDB',
        'TableHeader': 'E0F2F1',
    },
}

# ============================================================================
# Minimalist - Stark monochrome, high contrast and editorial
# Use case: Modern Resumes, Architecture portfolios, Legal contracts
# ============================================================================
Minimalist = {
    'Text': {
        'Primary': '000000',     # Black - headings
        'Secondary': '212121',   # Off-black - subheadings
        'Body': '424242',        # Dark grey - body
        'Muted': '9E9E9E',       # Light grey - captions
    },
    'Decorative': {
        'Muted': {
            'Primary': '4A4A4A',     # Dark grey - lines
            'Secondary': '7A7A7A',   # Medium grey - dividers
            'Accent': 'B0B0B0',      # Light grey - fills
        },
        'Vibrant': {
            'Primary': '000000',     # Black - bold lines
            'Secondary': '555555',   # Grey - dividers
            'Accent': 'E0E0E0',      # Light - backgrounds
        },
    },
    'UI': {
        'Border': 'EEEEEE',
        'TableHeader': 'F9F9F9',
    },
}

# ============================================================================
# Vitality - Fresh orange and green, food and wellness
# Use case: Supermarket flyers, Organic food menus, Community events
# WARNING: Orange/green for icons and shapes - text must be brown/neutral!
# ============================================================================
Vitality = {
    'Text': {
        'Primary': '3E2723',     # Dark brown - headings
        'Secondary': '4E3733',   # Medium brown - subheadings
        'Body': '5D4037',        # Cocoa - body text
        'Muted': '8D6E63',       # Light brown - captions
    },
    'Decorative': {
        'Muted': {
            'Primary': 'B07040',     # Muted orange - subtle
            'Secondary': '708050',   # Muted green - subtle
            'Accent': 'C0A080',      # Tan - fills
        },
        'Vibrant': {
            'Primary': 'F57C00',     # Orange - call to actions
            'Secondary': '689F38',   # Fresh green - nature
            'Accent': 'FF9800',      # Bright orange - accents
        },
    },
    'UI': {
        'Border': 'FFE0B2',
        'TableHeader': 'FFF3E0',
    },
}

# ============================================================================
# Midnight - Dark mode aesthetic, cyber and analytical
# Use case: Annual Cyber Reports, Gaming events, Developer docs
# WARNING: Neon blue/pink for accents only - use neutral slate for text!
# ============================================================================
Midnight = {
    'Text': {
        'Primary': '1E293B',     # Slate - headings
        'Secondary': '334155',   # Blue grey - subheadings
        'Body': '475569',        # Medium slate - body
        'Muted': '94A3B8',       # Light slate - captions
    },
    'Decorative': {
        'Muted': {
            'Primary': '3A4A5A',     # Muted slate - subtle
            'Secondary': '5A8090',   # Muted blue - subtle
            'Accent': '8A7080',      # Muted pink - fills
        },
        'Vibrant': {
            'Primary': '0F172A',     # Slate black - backgrounds
            'Secondary': '38BDF8',   # Sky blue - neon accents
            'Accent': 'F472B6',      # Pink - highlights
        },
    },
    'UI': {
        'Border': 'CBD5E1',
        'TableHeader': 'F1F5F9',
    },
}

# ============================================================================
# CoralReef - Warm pink and coral, lifestyle and fashion
# Use case: Beauty newsletters, Women's leadership, Magazine layouts
# WARNING: Coral/pink for decorative shapes - use muted brown-rose for text!
# ============================================================================
CoralReef = {
    'Text': {
        'Primary': '4A2C2C',     # Dark rose brown - headings
        'Secondary': '5A3C3C',   # Medium rose - subheadings
        'Body': '6A4C4C',        # Muted rose - body
        'Muted': '9A7A7A',       # Dusty rose - captions
    },
    'Decorative': {
        'Muted': {
            'Primary': 'A06060',     # Muted coral - subtle
            'Secondary': 'B08080',   # Dusty pink - subtle
            'Accent': 'C09090',      # Pale coral - fills
        },
        'Vibrant': {
            'Primary': 'E15F5F',     # Coral red - headers
            'Secondary': 'F48FB1',   # Pink - decorative
            'Accent': 'FF7070',      # Bright coral - accents
        },
    },
    'UI': {
        'Border': 'F8BBD0',
        'TableHeader': 'FFF0F5',
    },
}

# ============================================================================
# Financial - Trustworthy deep green and slate, banking and data
# Use case: Financial Statements, Quarterly earnings, Investment proposals
# ============================================================================
Financial = {
    'Text': {
        'Primary': '111827',     # Almost black - headings
        'Secondary': '1F2937',   # Dark slate - subheadings
        'Body': '374151',        # Charcoal - body
        'Muted': '6B7280',       # Grey - captions
    },
    'Decorative': {
        'Muted': {
            'Primary': '2A5A4A',     # Muted forest - subtle
            'Secondary': '4A7A6A',   # Muted teal - subtle
            'Accent': '90C0A8',      # Pale mint - fills
        },
        'Vibrant': {
            'Primary': '064E3B',     # Deep forest - headers
            'Secondary': '0F766E',   # Teal - charts
            'Accent': '10B981',      # Emerald - highlights
        },
    },
    'UI': {
        'Border': 'A7F3D0',
        'TableHeader': 'ECFDF5',
    },
}

# ============================================================================
# SCHEMES - All schemes indexed by name
# ============================================================================
SCHEMES = {
    'Morandi': Morandi,
    'InkWash': InkWash,
    'Corporate': Corporate,
    'Earth': Earth,
    'Nordic': Nordic,
    'French': French,
    'Academic': Academic,
    'Ocean': Ocean,
    'Forest': Forest,
    'Industrial': Industrial,
    'Desert': Desert,
    'RedPower': RedPower,
    'Luxury': Luxury,
    'Vibrant': Vibrant,
    'Innovation': Innovation,
    'Clinical': Clinical,
    'Minimalist': Minimalist,
    'Vitality': Vitality,
    'Midnight': Midnight,
    'CoralReef': CoralReef,
    'Financial': Financial,
}


def hex_to_css(hex_color: str) -> str:
    """Convert hex color (without #) to CSS format."""
    return f'#{hex_color}'


def get_scheme(name: str) -> dict:
    """Get color scheme by name. Raises KeyError if not found."""
    return SCHEMES[name]


def get_text_color(scheme_name: str, level: str = 'Body') -> str:
    """Get text color from scheme. level: Primary, Secondary, Body, Muted"""
    return SCHEMES[scheme_name]['Text'][level]


def get_decorative_color(scheme_name: str, style: str = 'Muted', level: str = 'Primary') -> str:
    """Get decorative color. style: Muted or Vibrant. level: Primary, Secondary, Accent"""
    return SCHEMES[scheme_name]['Decorative'][style][level]
