import createContextHook from '@nkzw/create-context-hook';
import { useRouter } from 'expo-router';
import React, { useCallback, useMemo, useRef, useState } from 'react';
import {
  Alert,
  Keyboard,
  KeyboardAvoidingView,
  Modal,
  Platform,
  Pressable,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from 'react-native';
import { X } from 'lucide-react-native';
import { useTheme } from '@/contexts/ThemeContext';

export const DEBUG_PIN = '1847';

function getConfiguredSuperAdminPin(): string {
  return process.env.EXPO_PUBLIC_SUPER_ADMIN_PIN || '';
}

export const [AdminAccessProvider, useAdminAccess] = createContextHook(() => {
  const router = useRouter();
  const { colors } = useTheme();

  const [isSuperAdmin, setIsSuperAdmin] = useState(false);
  const [isDebugMode, setIsDebugMode] = useState(false);
  const [showPinModal, setShowPinModal] = useState(false);
  const [pinInput, setPinInput] = useState('');
  const [pinError, setPinError] = useState('');

  const footerTapCountRef = useRef(0);
  const footerTapTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const authenticatedPinRef = useRef('');

  const exitSuperAdmin = useCallback(() => {
    setIsSuperAdmin(false);
    setIsDebugMode(false);
    authenticatedPinRef.current = '';
  }, []);

  const handleFooterTap = useCallback(() => {
    footerTapCountRef.current += 1;
    if (footerTapTimerRef.current) clearTimeout(footerTapTimerRef.current);
    if (footerTapCountRef.current >= 5) {
      footerTapCountRef.current = 0;
      if (isSuperAdmin || isDebugMode) {
        exitSuperAdmin();
      } else {
        setPinInput('');
        setPinError('');
        setShowPinModal(true);
      }
    } else {
      footerTapTimerRef.current = setTimeout(() => {
        footerTapCountRef.current = 0;
      }, 2000);
    }
  }, [isSuperAdmin, isDebugMode, exitSuperAdmin]);

  const submitPin = useCallback(() => {
    const configuredSuperAdminPin = getConfiguredSuperAdminPin();
    if (configuredSuperAdminPin && pinInput === configuredSuperAdminPin) {
      authenticatedPinRef.current = configuredSuperAdminPin;
      setIsSuperAdmin(true);
      setIsDebugMode(false);
      setShowPinModal(false);
      setPinInput('');
      setPinError('');
      router.push('/(tabs)/admin' as never);
      return;
    }
    if (pinInput === DEBUG_PIN) {
      setIsDebugMode(true);
      setIsSuperAdmin(false);
      setShowPinModal(false);
      setPinInput('');
      setPinError('');
      return;
    }
    setPinError('Incorrect PIN');
  }, [pinInput, router]);

  const pinModal = (
    <Modal
      visible={showPinModal}
      animationType="slide"
      transparent
      onRequestClose={() => setShowPinModal(false)}
    >
      <KeyboardAvoidingView
        style={{ flex: 1, justifyContent: 'flex-end', backgroundColor: 'rgba(0,0,0,0.5)' }}
        behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
      >
        <Pressable
          style={{ flex: 1 }}
          onPress={() => {
            Keyboard.dismiss();
            setShowPinModal(false);
          }}
        />
        <View
          style={{
            borderTopLeftRadius: 24,
            borderTopRightRadius: 24,
            padding: 20,
            backgroundColor: colors.surface,
          }}
        >
          <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <Text style={{ fontSize: 20, fontWeight: '600', color: colors.text }}>Advanced access</Text>
            <TouchableOpacity onPress={() => setShowPinModal(false)}>
              <X color={colors.textSecondary} size={24} />
            </TouchableOpacity>
          </View>
          <Text style={{ fontSize: 14, color: colors.textSecondary, marginBottom: 16 }}>
            Enter your PIN to open debug tools or admin controls.
          </Text>
          <View
            style={{
              backgroundColor: colors.background,
              borderColor: pinError ? colors.statusOverdue : colors.border,
              borderWidth: 1,
              borderRadius: 10,
              paddingHorizontal: 14,
              marginBottom: 8,
            }}
          >
            <TextInput
              style={{ color: colors.text, fontSize: 16, paddingVertical: 12 }}
              placeholder="Enter PIN"
              placeholderTextColor={colors.textSecondary}
              value={pinInput}
              onChangeText={(t) => {
                setPinInput(t);
                setPinError('');
              }}
              keyboardType="number-pad"
              secureTextEntry
              maxLength={10}
              onSubmitEditing={submitPin}
            />
          </View>
          {pinError ? (
            <Text style={{ color: colors.statusOverdue, fontSize: 13, marginBottom: 8 }}>{pinError}</Text>
          ) : null}
          <TouchableOpacity
            style={{
              backgroundColor: colors.statusOverdue,
              borderRadius: 10,
              paddingVertical: 14,
              alignItems: 'center',
            }}
            onPress={submitPin}
          >
            <Text style={{ color: '#fff', fontSize: 16, fontWeight: '600' }}>Unlock</Text>
          </TouchableOpacity>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );

  return useMemo(
    () => ({
      isSuperAdmin,
      isDebugMode,
      effectiveSuperAdminPin: isSuperAdmin ? authenticatedPinRef.current : '',
      handleFooterTap,
      exitSuperAdmin,
      pinModal,
    }),
    [isSuperAdmin, isDebugMode, handleFooterTap, exitSuperAdmin, pinModal],
  );
});
