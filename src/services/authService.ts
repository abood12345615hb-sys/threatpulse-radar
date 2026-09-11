import { supabase } from "@/lib/supabase";
import type { User } from "@/types";

export interface RegisterPayload {
  fullName: string;
  email: string;
  password: string;
  dialCode: string;
  phone: string;
  whatsappAlerts: boolean;
}

export const authService = {
  async current(): Promise<User | null> {
    if (typeof window === "undefined") return null;
    try {
      const { data: { session } } = await supabase.auth.getSession();
      if (!session) return null;

      // Fetch profile
      const { data: profile, error } = await supabase
        .from("profiles")
        .select("*")
        .eq("id", session.user.id)
        .single();

      if (error || !profile) {
        // Fallback to basic session info if profile is not found or fails
        return {
          id: session.user.id,
          fullName: session.user.user_metadata?.['full_name'] || session.user.email?.split("@")[0] || "User",
          email: session.user.email!,
          phone: session.user.user_metadata?.['whatsapp_number'] || "",
          whatsappAlerts: session.user.user_metadata?.['whatsapp_alerts_enabled'] || false,
          role: "analyst",
        };
      }

      return {
        id: profile.id,
        fullName: profile.full_name || session.user.email?.split("@")[0] || "User",
        email: session.user.email!,
        phone: profile.whatsapp_number || "",
        whatsappAlerts: profile.whatsapp_alerts_enabled || false,
        role: (profile.role as "analyst" | "admin") || "analyst",
      };
    } catch {
      return null;
    }
  },

  async register(payload: RegisterPayload): Promise<User> {
    const fullPhone = `${payload.dialCode}${payload.phone}`;

    // Check if phone already exists
    const { data: phoneExists, error: rpcError } = await supabase.rpc("check_phone_exists", { phone_number: fullPhone });
    if (rpcError) throw new Error(rpcError.message);
    if (phoneExists) {
      throw new Error("Phone already registered");
    }

    const { data, error } = await supabase.auth.signUp({
      email: payload.email,
      password: payload.password,
      options: {
        data: {
          full_name: payload.fullName,
          whatsapp_number: fullPhone,
          whatsapp_alerts_enabled: payload.whatsappAlerts,
        },
      },
    });

    if (error) throw new Error(error.message);
    
    // Supabase security feature: returns empty identities if user already exists
    if (data.user && data.user.identities && data.user.identities.length === 0) {
      throw new Error("User already registered");
    }
    
    if (!data.user) throw new Error("Signup failed");

    return {
      id: data.user.id,
      fullName: payload.fullName,
      email: payload.email,
      phone: fullPhone,
      whatsappAlerts: payload.whatsappAlerts,
      role: "analyst",
    };
  },

  async login(email: string, password: string): Promise<User> {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) throw new Error(error.message);
    if (!data.session) throw new Error("Login failed");

    // Fetch profile
    const { data: profile, error: profileError } = await supabase
      .from("profiles")
      .select("*")
      .eq("id", data.user.id)
      .single();

    if (profileError || !profile) {
      return {
        id: data.user.id,
        fullName: email.split("@")[0] || "User",
        email,
        phone: "",
        whatsappAlerts: false,
        role: "analyst",
      };
    }

    return {
      id: profile.id,
      fullName: profile.full_name || email.split("@")[0] || "User",
      email,
      phone: profile.whatsapp_number || "",
      whatsappAlerts: profile.whatsapp_alerts_enabled || false,
      role: (profile.role as "analyst" | "admin") || "analyst",
    };
  },

  async logout(): Promise<void> {
    await supabase.auth.signOut();
  },
};

export const COUNTRY_CODES = [
  { code: "SA", dial: "+966", label: "Saudi Arabia" },
  { code: "AE", dial: "+971", label: "United Arab Emirates" },
  { code: "EG", dial: "+20", label: "Egypt" },
  { code: "YE", dial: "+967", label: "Yemen" },
  { code: "JO", dial: "+962", label: "Jordan" },
  { code: "US", dial: "+1", label: "United States" },
  { code: "GB", dial: "+44", label: "United Kingdom" },
  { code: "DE", dial: "+49", label: "Germany" },
];
