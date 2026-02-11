// ColorSchemes.cs - Structured Color Palette Collection
//
// ⚠️ IMPORTANT DESIGN RULES FOR AGENT:
// 1. Text.* colors are for ALL text content - ALWAYS low saturation for readability
// 2. Decorative.Muted.* - low saturation decorative colors (subtle headers, professional look)
// 3. Decorative.Vibrant.* - high saturation decorative colors (eye-catching, bold designs)
// 4. NEVER use Decorative.Vibrant colors for text - damages readability
// 5. Choose Muted vs Vibrant based on document style (formal=Muted, promotional=Vibrant)
//
// Structure per scheme:
//   Text.Primary   - Main headings (low saturation, good contrast)
//   Text.Secondary - Subheadings (low saturation)
//   Text.Body      - Body text (low saturation, high readability)
//   Text.Muted     - Captions, helper text (low saturation, lighter)
//
//   Decorative.Muted.Primary/Secondary/Accent   - Subtle decorative elements
//   Decorative.Vibrant.Primary/Secondary/Accent - Bold decorative elements
//
//   UI.Border      - Table/box borders
//   UI.TableHeader - Table header background

namespace DocxProject;

public static class ColorSchemes
{
    // ============================================================================
    // Morandi - Soft muted tones, artistic and editorial
    // ============================================================================
    public static class Morandi
    {
        public static class Text
        {
            public const string Primary = "2d3a35";
            public const string Secondary = "4a5750";
            public const string Body = "5a6b62";
            public const string Muted = "8a9a90";
        }
        public static class Decorative
        {
            public static class Muted
            {
                public const string Primary = "7C9885";
                public const string Secondary = "8B9DC3";
                public const string Accent = "9CAF88";
            }
            public static class Vibrant
            {
                public const string Primary = "5A8066";
                public const string Secondary = "6B7FB0";
                public const string Accent = "7A9A60";
            }
        }
        public static class UI
        {
            public const string Border = "d8e0dc";
            public const string TableHeader = "f0f4f2";
        }
    }

    // ============================================================================
    // InkWash - Gray zen tones, traditional and contemplative
    // ============================================================================
    public static class InkWash
    {
        public static class Text
        {
            public const string Primary = "1A202C";
            public const string Secondary = "2D3748";
            public const string Body = "4A5568";
            public const string Muted = "A0AEC0";
        }
        public static class Decorative
        {
            public static class Muted
            {
                public const string Primary = "4A5568";
                public const string Secondary = "718096";
                public const string Accent = "A0AEC0";
            }
            public static class Vibrant
            {
                public const string Primary = "3A4558";
                public const string Secondary = "5A6A80";
                public const string Accent = "8090A0";
            }
        }
        public static class UI
        {
            public const string Border = "CBD5E0";
            public const string TableHeader = "EDF2F7";
        }
    }

    // ============================================================================
    // Corporate - Professional business blue
    // ============================================================================
    public static class Corporate
    {
        public static class Text
        {
            public const string Primary = "1A1A2E";
            public const string Secondary = "2E3A50";
            public const string Body = "3D5A80";
            public const string Muted = "8FA8C8";
        }
        public static class Decorative
        {
            public static class Muted
            {
                public const string Primary = "3D5A80";
                public const string Secondary = "6A8AA4";
                public const string Accent = "8AACBE";
            }
            public static class Vibrant
            {
                public const string Primary = "1E3A5F";
                public const string Secondary = "4A90A4";
                public const string Accent = "2E7090";
            }
        }
        public static class UI
        {
            public const string Border = "C4D4E0";
            public const string TableHeader = "E8EEF4";
        }
    }

    // ============================================================================
    // Earth - Brown and olive, natural and organic
    // ============================================================================
    public static class Earth
    {
        public static class Text
        {
            public const string Primary = "3D3229";
            public const string Secondary = "4D4239";
            public const string Body = "5D4E42";
            public const string Muted = "9A8B7A";
        }
        public static class Decorative
        {
            public static class Muted
            {
                public const string Primary = "6B5B4F";
                public const string Secondary = "8B7355";
                public const string Accent = "A08060";
            }
            public static class Vibrant
            {
                public const string Primary = "8B6040";
                public const string Secondary = "A67B5B";
                public const string Accent = "C08050";
            }
        }
        public static class UI
        {
            public const string Border = "D4C8BC";
            public const string TableHeader = "F2EDE8";
        }
    }

    // ============================================================================
    // Nordic - Cool gray and misty blue, minimalist and tech
    // ============================================================================
    public static class Nordic
    {
        public static class Text
        {
            public const string Primary = "2C3E4A";
            public const string Secondary = "3A4E5A";
            public const string Body = "4A6572";
            public const string Muted = "8A9EA8";
        }
        public static class Decorative
        {
            public static class Muted
            {
                public const string Primary = "5A7080";
                public const string Secondary = "7A909A";
                public const string Accent = "90A8B0";
            }
            public static class Vibrant
            {
                public const string Primary = "4A5D6B";
                public const string Secondary = "6B8E9B";
                public const string Accent = "5080A0";
            }
        }
        public static class UI
        {
            public const string Border = "C8D4DA";
            public const string TableHeader = "ECF0F3";
        }
    }

    // ============================================================================
    // French - Off-white and dusty pink, luxury and feminine
    // ============================================================================
    public static class French
    {
        public static class Text
        {
            public const string Primary = "4A3F3F";
            public const string Secondary = "5A4848";
            public const string Body = "6B5858";
            public const string Muted = "A89898";
        }
        public static class Decorative
        {
            public static class Muted
            {
                public const string Primary = "9E7B7B";
                public const string Secondary = "B8A9A9";
                public const string Accent = "C4B0B0";
            }
            public static class Vibrant
            {
                public const string Primary = "C08080";
                public const string Secondary = "D4A0A0";
                public const string Accent = "E0B0B0";
            }
        }
        public static class UI
        {
            public const string Border = "DDD4D4";
            public const string TableHeader = "F5F0F0";
        }
    }

    // ============================================================================
    // Academic - Navy and burgundy, research and education
    // ============================================================================
    public static class Academic
    {
        public static class Text
        {
            public const string Primary = "1A252F";
            public const string Secondary = "2A3540";
            public const string Body = "4A5A6A";
            public const string Muted = "8A9AA8";
        }
        public static class Decorative
        {
            public static class Muted
            {
                public const string Primary = "4A5A70";
                public const string Secondary = "6A4A4A";
                public const string Accent = "7A6050";
            }
            public static class Vibrant
            {
                public const string Primary = "2C3E50";
                public const string Secondary = "8B3030";
                public const string Accent = "A06030";
            }
        }
        public static class UI
        {
            public const string Border = "D4D8DC";
            public const string TableHeader = "F5F5F0";
        }
    }

    // ============================================================================
    // Ocean - Misty blue and sand, marine and wellness
    // ============================================================================
    public static class Ocean
    {
        public static class Text
        {
            public const string Primary = "2A4A5A";
            public const string Secondary = "3A5A6A";
            public const string Body = "4A6A7A";
            public const string Muted = "8A9AA8";
        }
        public static class Decorative
        {
            public static class Muted
            {
                public const string Primary = "6A8A9A";
                public const string Secondary = "8AAAB0";
                public const string Accent = "A0C0C4";
            }
            public static class Vibrant
            {
                public const string Primary = "4080A0";
                public const string Secondary = "60B0C0";
                public const string Accent = "40A0B0";
            }
        }
        public static class UI
        {
            public const string Border = "C8DDE4";
            public const string TableHeader = "EEF4F6";
        }
    }

    // ============================================================================
    // Forest - Olive and moss green, nature and sustainability
    // ============================================================================
    public static class Forest
    {
        public static class Text
        {
            public const string Primary = "2A3A2A";
            public const string Secondary = "3A4A3A";
            public const string Body = "4A5A3A";
            public const string Muted = "8A9A7A";
        }
        public static class Decorative
        {
            public static class Muted
            {
                public const string Primary = "5A6B4A";
                public const string Secondary = "7A8B5A";
                public const string Accent = "8B9B6A";
            }
            public static class Vibrant
            {
                public const string Primary = "4A7040";
                public const string Secondary = "60A050";
                public const string Accent = "70B060";
            }
        }
        public static class UI
        {
            public const string Border = "C8D4C4";
            public const string TableHeader = "EEF2EC";
        }
    }

    // ============================================================================
    // Industrial - Charcoal and rust, manufacturing and engineering
    // ============================================================================
    public static class Industrial
    {
        public static class Text
        {
            public const string Primary = "2D2D2D";
            public const string Secondary = "3D3D3D";
            public const string Body = "5A5A5A";
            public const string Muted = "8A8A8A";
        }
        public static class Decorative
        {
            public static class Muted
            {
                public const string Primary = "5A5A5A";
                public const string Secondary = "7A6A5A";
                public const string Accent = "8A7A60";
            }
            public static class Vibrant
            {
                public const string Primary = "4A4A4A";
                public const string Secondary = "A07050";
                public const string Accent = "C08040";
            }
        }
        public static class UI
        {
            public const string Border = "C8C8C8";
            public const string TableHeader = "EBEBEB";
        }
    }

    // ============================================================================
    // Desert - Ochre and sandy gold, warm and regional
    // ============================================================================
    public static class Desert
    {
        public static class Text
        {
            public const string Primary = "4A3A2A";
            public const string Secondary = "5A4A3A";
            public const string Body = "7A6A4A";
            public const string Muted = "A89A7A";
        }
        public static class Decorative
        {
            public static class Muted
            {
                public const string Primary = "907050";
                public const string Secondary = "A89070";
                public const string Accent = "C0A080";
            }
            public static class Vibrant
            {
                public const string Primary = "C08040";
                public const string Secondary = "D4A060";
                public const string Accent = "E0B070";
            }
        }
        public static class UI
        {
            public const string Border = "DDD4C4";
            public const string TableHeader = "F5F0E8";
        }
    }

    // ============================================================================
    // RedPower - Authoritative and solemn, for Party/Government documents
    // Use case: Government reports, Party propaganda, Official notices
    // ⚠️ Vibrant red is for decorative use ONLY - never for body text!
    // ============================================================================
    public static class RedPower
    {
        public static class Text
        {
            public const string Primary = "2B1212";     // Deep warm black - main headings
            public const string Secondary = "3B2222";   // Dark brown - subheadings
            public const string Body = "594949";        // Warm grey - body text
            public const string Muted = "9E8888";       // Muted mauve - captions
        }
        public static class Decorative
        {
            public static class Muted
            {
                public const string Primary = "8B4040";     // Muted red - subtle headers
                public const string Secondary = "A08060";   // Muted gold - subtle lines
                public const string Accent = "D8C8B0";      // Pale cream - fills
            }
            public static class Vibrant
            {
                public const string Primary = "B82525";     // China Red - bold headers
                public const string Secondary = "CFA972";   // Gold - decorative lines
                public const string Accent = "D42020";      // Bright red - accents
            }
        }
        public static class UI
        {
            public const string Border = "E6C7C7";
            public const string TableHeader = "FFF5F5";
        }
    }

    // ============================================================================
    // Luxury - Black and Gold, high-end and exclusive
    // Use case: Fine dining menus, VIP invitations, Real Estate brochures
    // ============================================================================
    public static class Luxury
    {
        public static class Text
        {
            public const string Primary = "000000";     // Pure black - headings
            public const string Secondary = "1A1A1A";   // Rich black - subheadings
            public const string Body = "4A4A4A";        // Dark grey - body
            public const string Muted = "8C8C8C";       // Silver grey - captions
        }
        public static class Decorative
        {
            public static class Muted
            {
                public const string Primary = "3A3A3A";     // Soft black - frames
                public const string Secondary = "9A8050";   // Muted gold - borders
                public const string Accent = "C8B890";      // Pale gold - fills
            }
            public static class Vibrant
            {
                public const string Primary = "1A1A1A";     // Rich black - frames
                public const string Secondary = "C5A059";   // Metallic gold - borders
                public const string Accent = "D4AF37";      // Bright gold - highlights
            }
        }
        public static class UI
        {
            public const string Border = "DECBA5";
            public const string TableHeader = "FAF8F5";
        }
    }

    // ============================================================================
    // Vibrant - High energy yellow and black, bold and loud
    // Use case: Recruitment flyers, Sale posters, Gym promos
    // ⚠️ Yellow is for backgrounds/shapes ONLY - use black text for readability!
    // ============================================================================
    public static class Vibrant
    {
        public static class Text
        {
            public const string Primary = "000000";     // Black - all headings
            public const string Secondary = "1A1A1A";   // Near black - subheadings
            public const string Body = "404040";        // Dark grey - body text
            public const string Muted = "666666";       // Medium grey - captions
        }
        public static class Decorative
        {
            public static class Muted
            {
                public const string Primary = "C0A820";     // Muted yellow - subtle
                public const string Secondary = "3A3A3A";   // Dark grey - subtle contrast
                public const string Accent = "A09020";      // Olive yellow - accents
            }
            public static class Vibrant
            {
                public const string Primary = "FFD700";     // Electric yellow - backgrounds
                public const string Secondary = "000000";   // Black - contrast shapes
                public const string Accent = "FFC000";      // Gold yellow - accents
            }
        }
        public static class UI
        {
            public const string Border = "E6C200";
            public const string TableHeader = "FFFFE0";
        }
    }

    // ============================================================================
    // Innovation - Electric purple and indigo, modern SaaS and Tech
    // Use case: Software whitepapers, Tech conferences, Startup pitch decks
    // ⚠️ Vibrant purple for buttons/shapes - use desaturated colors for text!
    // ============================================================================
    public static class Innovation
    {
        public static class Text
        {
            public const string Primary = "1E1B4B";     // Deep indigo - headings
            public const string Secondary = "312E81";   // Dark purple - subheadings
            public const string Body = "4A4766";        // Muted purple-grey - body
            public const string Muted = "8A88A0";       // Grey lavender - captions
        }
        public static class Decorative
        {
            public static class Muted
            {
                public const string Primary = "5A5090";     // Muted indigo - subtle
                public const string Secondary = "7060A0";   // Muted violet - subtle
                public const string Accent = "A0A0C0";      // Grey purple - fills
            }
            public static class Vibrant
            {
                public const string Primary = "4F46E5";     // Indigo - header bars
                public const string Secondary = "7C3AED";   // Violet - buttons
                public const string Accent = "8B5CF6";      // Purple - highlights
            }
        }
        public static class UI
        {
            public const string Border = "E0E7FF";
            public const string TableHeader = "F5F3FF";
        }
    }

    // ============================================================================
    // Clinical - Clean teal and sterile white, medical and hygiene
    // Use case: Hospital reports, Health checkups, Pharmaceutical guides
    // ⚠️ Bright teal for decorative only - text must be dark and readable!
    // ============================================================================
    public static class Clinical
    {
        public static class Text
        {
            public const string Primary = "1A3A38";     // Very dark teal - headings
            public const string Secondary = "2A4A48";   // Dark teal - subheadings
            public const string Body = "3A5A58";        // Muted teal - body
            public const string Muted = "6A8A88";       // Grey teal - captions
        }
        public static class Decorative
        {
            public static class Muted
            {
                public const string Primary = "4A7A70";     // Muted teal - subtle
                public const string Secondary = "6A9A90";   // Soft teal - subtle
                public const string Accent = "90B0A8";      // Grey teal - fills
            }
            public static class Vibrant
            {
                public const string Primary = "00897B";     // Teal - header bars
                public const string Secondary = "26A69A";   // Light teal - accents
                public const string Accent = "00BFA5";      // Bright teal - highlights
            }
        }
        public static class UI
        {
            public const string Border = "B2DFDB";
            public const string TableHeader = "E0F2F1";
        }
    }

    // ============================================================================
    // Minimalist - Stark monochrome, high contrast and editorial
    // Use case: Modern Resumes, Architecture portfolios, Legal contracts
    // ============================================================================
    public static class Minimalist
    {
        public static class Text
        {
            public const string Primary = "000000";     // Black - headings
            public const string Secondary = "212121";   // Off-black - subheadings
            public const string Body = "424242";        // Dark grey - body
            public const string Muted = "9E9E9E";       // Light grey - captions
        }
        public static class Decorative
        {
            public static class Muted
            {
                public const string Primary = "4A4A4A";     // Dark grey - lines
                public const string Secondary = "7A7A7A";   // Medium grey - dividers
                public const string Accent = "B0B0B0";      // Light grey - fills
            }
            public static class Vibrant
            {
                public const string Primary = "000000";     // Black - bold lines
                public const string Secondary = "555555";   // Grey - dividers
                public const string Accent = "E0E0E0";      // Light - backgrounds
            }
        }
        public static class UI
        {
            public const string Border = "EEEEEE";
            public const string TableHeader = "F9F9F9";
        }
    }

    // ============================================================================
    // Vitality - Fresh orange and green, food and wellness
    // Use case: Supermarket flyers, Organic food menus, Community events
    // ⚠️ Orange/green for icons and shapes - text must be brown/neutral!
    // ============================================================================
    public static class Vitality
    {
        public static class Text
        {
            public const string Primary = "3E2723";     // Dark brown - headings
            public const string Secondary = "4E3733";   // Medium brown - subheadings
            public const string Body = "5D4037";        // Cocoa - body text
            public const string Muted = "8D6E63";       // Light brown - captions
        }
        public static class Decorative
        {
            public static class Muted
            {
                public const string Primary = "B07040";     // Muted orange - subtle
                public const string Secondary = "708050";   // Muted green - subtle
                public const string Accent = "C0A080";      // Tan - fills
            }
            public static class Vibrant
            {
                public const string Primary = "F57C00";     // Orange - call to actions
                public const string Secondary = "689F38";   // Fresh green - nature
                public const string Accent = "FF9800";      // Bright orange - accents
            }
        }
        public static class UI
        {
            public const string Border = "FFE0B2";
            public const string TableHeader = "FFF3E0";
        }
    }

    // ============================================================================
    // Midnight - Dark mode aesthetic, cyber and analytical
    // Use case: Annual Cyber Reports, Gaming events, Developer docs
    // ⚠️ Neon blue/pink for accents only - use neutral slate for text!
    // ============================================================================
    public static class Midnight
    {
        public static class Text
        {
            public const string Primary = "1E293B";     // Slate - headings
            public const string Secondary = "334155";   // Blue grey - subheadings
            public const string Body = "475569";        // Medium slate - body
            public const string Muted = "94A3B8";       // Light slate - captions
        }
        public static class Decorative
        {
            public static class Muted
            {
                public const string Primary = "3A4A5A";     // Muted slate - subtle
                public const string Secondary = "5A8090";   // Muted blue - subtle
                public const string Accent = "8A7080";      // Muted pink - fills
            }
            public static class Vibrant
            {
                public const string Primary = "0F172A";     // Slate black - backgrounds
                public const string Secondary = "38BDF8";   // Sky blue - neon accents
                public const string Accent = "F472B6";      // Pink - highlights
            }
        }
        public static class UI
        {
            public const string Border = "CBD5E1";
            public const string TableHeader = "F1F5F9";
        }
    }

    // ============================================================================
    // CoralReef - Warm pink and coral, lifestyle and fashion
    // Use case: Beauty newsletters, Women's leadership, Magazine layouts
    // ⚠️ Coral/pink for decorative shapes - use muted brown-rose for text!
    // ============================================================================
    public static class CoralReef
    {
        public static class Text
        {
            public const string Primary = "4A2C2C";     // Dark rose brown - headings
            public const string Secondary = "5A3C3C";   // Medium rose - subheadings
            public const string Body = "6A4C4C";        // Muted rose - body
            public const string Muted = "9A7A7A";       // Dusty rose - captions
        }
        public static class Decorative
        {
            public static class Muted
            {
                public const string Primary = "A06060";     // Muted coral - subtle
                public const string Secondary = "B08080";   // Dusty pink - subtle
                public const string Accent = "C09090";      // Pale coral - fills
            }
            public static class Vibrant
            {
                public const string Primary = "E15F5F";     // Coral red - headers
                public const string Secondary = "F48FB1";   // Pink - decorative
                public const string Accent = "FF7070";      // Bright coral - accents
            }
        }
        public static class UI
        {
            public const string Border = "F8BBD0";
            public const string TableHeader = "FFF0F5";
        }
    }

    // ============================================================================
    // Financial - Trustworthy deep green and slate, banking and data
    // Use case: Financial Statements, Quarterly earnings, Investment proposals
    // ============================================================================
    public static class Financial
    {
        public static class Text
        {
            public const string Primary = "111827";     // Almost black - headings
            public const string Secondary = "1F2937";   // Dark slate - subheadings
            public const string Body = "374151";        // Charcoal - body
            public const string Muted = "6B7280";       // Grey - captions
        }
        public static class Decorative
        {
            public static class Muted
            {
                public const string Primary = "2A5A4A";     // Muted forest - subtle
                public const string Secondary = "4A7A6A";   // Muted teal - subtle
                public const string Accent = "90C0A8";      // Pale mint - fills
            }
            public static class Vibrant
            {
                public const string Primary = "064E3B";     // Deep forest - headers
                public const string Secondary = "0F766E";   // Teal - charts
                public const string Accent = "10B981";      // Emerald - highlights
            }
        }
        public static class UI
        {
            public const string Border = "A7F3D0";
            public const string TableHeader = "ECFDF5";
        }
    }
}
